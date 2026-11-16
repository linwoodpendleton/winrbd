# winrbd core architecture (Phase 1)

<!-- SPDX-License-Identifier: MIT -->

Status: **design for Phase 1, milestones 1 to 3, plus delivery of the monitor's map messages as raw bytes.** The skeleton described in section 6 is in the tree and builds; the modules are implemented in the waves of section 9. Everything here is our own design, written from `docs/spec/`; Ceph, iPXE, WNBD and Linux kernel code is not copied (see [CONTRIBUTING.md](../../CONTRIBUTING.md), rule 1). Spec notes are cited as `msgr2.md 2.3`, `cephx.md 3.2`, and so on.

Scope of this run (ROADMAP Phase 1):

| Milestone | In scope |
|---|---|
| 1. Shim interface, Linux implementation | yes: `wr_host.h`, the pump API, `harness/host/` |
| 2. Monitor over msgr2 (banner, hello, frames, CRC-32C) | yes |
| 3. cephx, tickets for mon and OSD services, renewal | yes (both key types, mon handshake, OSD authorizer, in-session renewal) |
| 4. OSDMap | only receiving `MMonMap` and `MOSDMap` from the monitor, raw; no decoding of maps |
| 5 to 11 (CRUSH, OSD sessions, RBD, krbd compare, fuzzing of those decoders, secure mode) | later; section 10 records the hooks that keep them cheap |

Contents: 1 decisions at a glance, 2 language and portability rules, 3 hosting model (the pump), 4 shim and crypto, 5 memory model, 6 source layout, 7 module interfaces, 8 state machines, 9 implementation waves, 10 later milestones, 11 error model and logging, 12 build, tests, fuzzing, 13 where the alternatives disagreed, 14 risks and open questions.

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
| D10 | Source layout | `core/include/winrbd/` public headers; `core/src/<module>/` internals; **unique C basenames** (iPXE names objects by basename); `core/sources.txt` generated; `core/crush_ln/` reserved for the LGPL tables. |
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
- `core/crush_ln/` is reserved for the LGPL-licensed CRUSH log tables and is not part of this run. The CRUSH module will call a single declared function (`wri_crush_ln`) so the licence boundary is one symbol and one directory; until the real directory lands the harness supplies a test-only stub.

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

These numbers are **first estimates**. The footprint test (`test_client_mem`, `test_core_budgets`) prints the real byte counts and asserts the budgets once the engine exists; the profile numbers in `core/src/client/wr_config.c` are then tuned. Rough shape of the iPXE arena: 4 connections x (4 KiB ring + 8 KiB control + 8 KiB encode) is about 80 KiB, one handshake slot 16 KiB, tickets and keys a few KiB; the bulk region is one 1 MiB message slot. The iPXE heap headroom next to iPXE's own users is unmeasured (risk R1).

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

Later milestones add `osdmap/`, `crush/`, `osd/`, `rbd/` and `core/crush_ln/` next to these.

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

Seven waves, 19 modules. Modules of one wave touch disjoint files and can be implemented in parallel by different people; a wave depends only on earlier waves. The critical path is `util-core -> denc-addr -> m2-ctl -> m2-conn -> mon-client -> client-engine -> linux-host-loop`.

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

**OSDMap and CRUSH (milestones 4 and 5).** Decoders are pure functions over cursors with a two-pass **validate-then-apply** for incrementals (a failed validation leaves the held map untouched); the CRUSH blob is kept as received with an offset index; two map slots in the bulk region so I/O continues during a full-map swap (`osdmap_slots`, or one slot with a pause on small hosts); `wri_crush_ln` is the single LGPL seam. The raw messages this run delivers are exactly the input of those decoders.

**Secure mode (milestone 11).** `m2_codec_secure` behind the codec seam: AES-128-GCM, 16-byte key and two 12-byte nonces from the 64-byte connection secret, up to three AEAD operations per frame, secure data transmitted through a per-connection bounce buffer (the caller's write buffer must not be modified). New primitive members are added to `wr_prim_ops` behind `size`.

**Crash dump and hibernation (Phase 5).** Index-based, relocatable state keeps the option of serialising the minimum a dump-mode engine needs; nothing is built for it.

---

## 11. Error model and logging

### 11.1 Status codes

`wr_status` is `int32_t`: 0 success, `-(code)` failure. The code list is one X-macro (`WR_STATUS_LIST` in `wr_err.h`) with names and English texts, in ranges per module: 1 to 19 generic, 20 to 39 host and crypto, 40 to 79 msgr2, 80 to 99 cephx, 100 to 119 monitor client, 120 to 239 reserved for maps, CRUSH, OSD client and RBD. `wr_strerror` and `wr_status_name` render them (static strings, no formatting, hosts localise by code). No `errno`, no exceptions, no assert that can fire on untrusted input; a decoder returns a status and never trusts a length.

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

`harness/fuzz/fuzz_<target>.c` defines `LLVMFuzzerTestOneInput`. With `-DWR_FUZZ=ON` (clang) it is a libFuzzer binary with ASan and UBSan; otherwise it is linked with `fuzz_replay_main.c` and ctest replays `harness/fuzz/seeds/<target>/` as `fuzzseed.<target>`, so the committed corpus is a regression test on every run. (The directory is `seeds/`, not `corpus/`, because `.gitignore` excludes `corpus/`.) Targets, one per decoder boundary: `util_cursor`, `denc_addr`, `m2_rx`, `m2_ctl`, `m2_conn`, `cx_envelope`, `cx_reply`, `mon_msgs`, `mon_session`, and the whole-engine `client_session`. Properties asserted in every target: no crash or undefined behaviour, no read or write outside the input and sinks, memory inside the arena, and a decoder that succeeds consumed exactly what its envelope said. Proposed duration for the Phase 1 exit criterion ("agreed duration"): 60 s per target on every push, 1 h nightly, 8 CPU-hours per target before milestone 10 closes; the maintainer decides. Every crasher is minimised and committed under `seeds/`.

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

Open questions for the maintainers (defaults stand unless answered):

- **Q1.** Ratify **C99** and **own crypto with host override** (sections 2.1, 4.2).
- **Q2.** Ratify the **two-region memory model** and the profile budgets after the first footprint run.
- **Q3.** Entity naming convention: `wr_cluster_spec.user` is the id without the type (`winrbd` for `client.winrbd`); a leading `client.` is stripped.
- **Q4.** Whether OSDs accept `mtime` 0 from a host without a wall clock (needs a lab check when writes exist).
- **Q5.** Hostname resolution stays outside the core (literal addresses): resolved by iPXE before the call, by user space on Windows and passed through the handoff table.
- **Q6.** Fuzzing duration for the exit criterion (proposal in 12.3).
