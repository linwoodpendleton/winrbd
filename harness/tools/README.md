# harness/tools: Phase 0 checkers

<!-- SPDX-License-Identifier: MIT -->

Independent checkers for the protocol notes in [docs/spec/](../../docs/spec/README.md). Each one was written from its note alone (no Ceph decoder, no Ceph code), parses the lab captures and tool output, and fails if the note and the bytes disagree. They also write and verify the scrubbed test vectors in [../vectors/](../vectors/).

License: MIT. Every file carries `SPDX-License-Identifier: MIT`.

## What is here

| Tool | Checks note | Vectors | Needs captures |
|---|---|---|---|
| `msgr2_check.py` | [msgr2.md](../../docs/spec/msgr2.md) | `vectors/msgr2/` | yes, or `--check-vectors <dir>` alone |
| `secure_check.py` | [msgr2-secure-mode.md](../../docs/spec/msgr2-secure-mode.md) | `vectors/secure/` | yes |
| `cephx_check.py` | [cephx.md](../../docs/spec/cephx.md) | `vectors/cephx/` | yes, or `--vectors <dir>` alone |
| `monclient_check.py` | [mon-client.md](../../docs/spec/mon-client.md) | `vectors/monclient/` | yes |
| `osdmap_check.py` | [osdmap.md](../../docs/spec/osdmap.md) | `vectors/osdmap/` | optional (without it only the vectors are checked) |
| `crush_check.py` | [crush-and-placement.md](../../docs/spec/crush-and-placement.md) | `vectors/crush/` | yes |
| `osdop_check.py` | [osd-ops.md](../../docs/spec/osd-ops.md) | `vectors/osdop/` | yes, or `--vectors-only` |
| `rbd_check.py` | [rbd-format2.md](../../docs/spec/rbd-format2.md) | `vectors/rbd/` | yes, or `--vectors-only` |
| `wire.py` | (shared helpers: CRC-32C, reader, pcap and TCP reassembly, msgr2 and cephx primitives) | | |
| `msgr2_probe.py` | (live probe, see below) | | no, needs a lab monitor |

The other checkers carry their own helpers; only `monclient_check.py` imports `wire.py`. Each vector directory has a README on provenance, scrubbing and how its files are regenerated.

## Requirements

- Python 3 (run with 3.14.6) and the `cryptography` package (run with 46.0.3). Nothing else: no Ceph installation, no network, no root.
- The checkers only read. They write nothing unless you pass an explicit `--emit-vectors` / `--write-vectors` / `--export-vectors` option. Use `PYTHONDONTWRITEBYTECODE=1` so that no `__pycache__` appears in the working tree.
- Run them as scripts from the repository root (`python3 harness/tools/<name>.py ...`).
- Keys are read at run time from the private lab store and are never printed.

## Where captures and secrets live (outside the repository)

Everything below is private lab material and must never be added to this repository (see [CONTRIBUTING.md](../../CONTRIBUTING.md), rule 4). By convention it sits in a directory next to the checkout:

```
<parent>/winrbd/                        this repository
<parent>/winrbd-ref/ceph-v20.2.5/       read-only reference source tree (the pinned release)
<parent>/winrbd-ref/captures/           raw captures; mode 0700
    pcap/  sessions.tsv  gt*/ data/ logs/ stdout/ MANIFEST.md
    secrets/                            session secrets and full debug logs; mode 0700
<parent>/winrbd-ref/lab-secrets/        lab keyrings; mode 0700
<parent>/winrbd-ref/lab-facts/          cluster facts without secrets
<parent>/winrbd-ref/tools/              helpers that link or import Ceph code (never in this repository)
```

Defaults: `--keys` falls back to `<captures>/../lab-secrets` (and `<captures>/secrets/keys`); `--ref` falls back to `<repo>/../winrbd-ref/ceph-v20.2.5`. Pass the paths explicitly if your layout differs. Keep the directories at mode 0700 and out of backups that leave the machine.

## Running everything

From the repository root, with `C` set to the captures directory:

```sh
export PYTHONDONTWRITEBYTECODE=1
C=<parent>/winrbd-ref/captures

python3 harness/tools/msgr2_check.py     --captures "$C"
python3 harness/tools/secure_check.py    --captures "$C"
python3 harness/tools/cephx_check.py     --captures "$C" --vectors harness/vectors/cephx
python3 harness/tools/monclient_check.py --captures "$C"
python3 harness/tools/osdmap_check.py    --captures "$C"
python3 harness/tools/crush_check.py     --captures "$C"
python3 harness/tools/osdop_check.py     --captures "$C"
python3 harness/tools/rbd_check.py       --captures "$C"
```

The checkers are independent; run them in parallel if you like (about a minute wall time on a laptop). Every one exits 0 when all checks pass and non-zero when any check fails. Lines starting with `WARNING`, `note[...]` or `info` are not failures: the captures `k1-rbd-bench-default` and `k1-sec-rados-big` lost packets on the 9 MiB transfers (tcpdump kernel drops), and the checkers analyse those streams only up to the hole and say so.

Without any capture set, the committed vectors can still be verified:

```sh
python3 harness/tools/msgr2_check.py --check-vectors harness/vectors/msgr2
python3 harness/tools/cephx_check.py --vectors harness/vectors/cephx
python3 harness/tools/osdop_check.py --vectors-only
python3 harness/tools/rbd_check.py   --vectors-only
python3 harness/tools/osdmap_check.py          # vectors and self-tests only
```

`crush_check.py` has two speed options: `--quick` (skip large-segment CRCs and the in-tree group) and `--tree-x N` (how many inputs per in-tree known-answer file; default 8, 1024 means whole files and takes minutes).

### Reference run

All eight against the Phase 0 capture set (39 pcaps), 2026-11-16, every one exit 0:

| Tool | Result | Time |
|---|---|---|
| `msgr2_check.py` | 177,628 checks passed, 0 failed (74 check ids) | 55 s |
| `secure_check.py` | 151,305 checks passed, 0 failed | 41 s |
| `cephx_check.py` | 84,714 checks on captures, 954 on vectors, 0 failed | 10 s |
| `monclient_check.py` | 206 named checks, 64,830 assertions, 0 failed | 8 s |
| `osdmap_check.py` | 119 checks passed, 0 failed | 46 s |
| `crush_check.py` | 80 checks passed, 0 failed (636,903 comparisons) | 60 to 87 s |
| `osdop_check.py` | 119,197 checks passed, 0 failed | 9 s |
| `rbd_check.py` | 6,891 checks passed, 0 failed | 27 s |

Offline vector runs: msgr2 68 passed, cephx all passed, osdop 219 passed, rbd 172 passed, osdmap 52 passed (self-tests and vectors).

## Live probe: `msgr2_probe.py`

A small msgr2 / cephx client that sends deliberately unusual frames to one monitor to settle questions a stock client cannot answer (banner variants, alignments, message flags, duplicate sequence numbers, feature-bit masks). It is the only tool here that opens a network connection.

- Point it only at a lab cluster you own and can afford to break: some experiments make the monitor close the connection, and the notes record one (non-power-of-two alignment) that was deliberately not tried because it could crash the only monitor.
- Needs a keyring (`--keyring`) and the monitor address (`--mon`, default `10.77.0.10:3300`, the lab default); `--entity` defaults to `client.winrbd`.
- The results it produced are written up in `docs/spec/msgr2.md` (section 6) and `harness/vectors/msgr2/README.md`.

## Licensing rule for Ceph data (run-time loading only)

- The tools and the vectors are our own work, MIT. They contain no Ceph source, comments or lookup tables.
- A check that needs data which exists only in Ceph's sources loads it at run time from the reference tree and never embeds it. The CRUSH fixed-point log tables (`RH_LH`, `LL_tbl`) are parsed from `<ref>/src/crush/crush_ln_table.h` when `osdmap_check.py` or `crush_check.py` run (`--ref <tree>`); without the tree `osdmap_check.py` reports those checks as skipped and `crush_check.py` fails the groups that need them (it cannot run them). The vectors carry only computed outputs (a handful of `crush_ln` results), never the tables. This keeps licensing question L1 in [docs/spec/README.md](../../docs/spec/README.md) section 8 open without the repository depending on its answer.
- The same holds for Ceph's test inputs: the in-tree CRUSH known-answer files are read from `<ref>` at run time (`crush_check.py` group F) and never copied here; cephx type-2 vectors come from RFC 8009, typed from the RFC.
- Ceph tools (`ceph`, `rbd`, `rados`, `crushtool`, `osdmaptool`, `ceph-dencoder`, `ceph-monstore-tool`) are used only as oracles in the lab; what lands in the capture directory is their output. Do not run them from this repository, and do not decode with them inside a checker.
- A tool that links, compiles or imports Ceph code (oracle helpers built from the reference C files, for example) lives under `<parent>/winrbd-ref/tools/`, never in this repository, and its output code is never copied in.

## Secrets rule

- Raw captures, keyrings, `debug_auth` logs, session keys, tickets, connection secrets and decrypted authentication payloads stay in `winrbd-ref/` (mode 0700).
- A vector is committed only if it is scrubbed: key material, key-derived nonces, tickets, signatures and encrypted blobs are replaced by labelled placeholders of the same length, or only structure (lengths, offsets) is kept. The scrubbing of each vector directory is explained in its README.
- The `--emit-vectors` options of the writers run a leak guard (`msgr2_check.py` compares its output with every key and session key known to the capture set and deletes the files on a hit). There is no single repository-wide scrub script yet.
- Allow-list for scans: the four `harness/vectors/cephx/session-*.json` files contain a `keyring_key_base64` that looks like a cephx key. These are **synthetic** (derived from public labels by `cephx_check.py`), not lab keys; a scan that flags them is right to ask and the answer is in the file's `description`.

### Manual scan before committing or publishing

Run from the repository root; each command should print nothing, apart from the allow-listed hits noted:

```sh
# keyring lines
grep -rIn --exclude-dir=.git --exclude-dir=third_party -E '^\s*key\s*=\s*\S+' . | grep -v '\.py:'
# base64 strings of cephx key length (40 chars starting AQ, 60 chars starting Ag) or any long base64 with padding
grep -rIn --exclude-dir=.git --exclude-dir=third_party -E 'AQ[A-Za-z0-9+/]{30,}|Ag[A-Za-z0-9+/]{50,}|[A-Za-z0-9+/]{38,}={1,2}' .      # allowed: the four cephx session-*.json (synthetic)
# addresses: only the lab range 10.77.0.x, documentation ranges and loopback may appear
grep -rIhoE --exclude-dir=.git --exclude-dir=third_party '\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b' . | sort | uniq -c | sort -rn
# names that must not appear in repository files
grep -rIniE --exclude-dir=.git --exclude-dir=third_party '/Users/|/home/[a-z]|@[a-z0-9-]+\.(com|net|org|io|cn)' .
```

A stronger check compares the repository with every secret the capture set knows: collect every base64 and 32+ hex token from `winrbd-ref/lab-secrets` and `winrbd-ref/captures/secrets`, derive their raw and hex forms, and search the repository for each. The scan used before the Phase 0 publication did exactly this over 2,417 candidates and found 0 hits (and it does find them when pointed at the raw log directory, which proves it can see). The cluster fsid and the lab monitor name appear in two `monclient` vectors; they are not secrets.

## Regenerating vectors

Each vector directory's README gives the exact command. In short: `msgr2_check.py --emit-vectors <dir>`, `secure_check.py --export-vectors <dir>`, `cephx_check.py --emit-vectors <dir>`, `monclient_check.py --write-vectors <dir>`, `osdmap_check.py --write-vectors`, `crush_check.py --emit-vectors <dir>`, `osdop_check.py --emit-vectors <dir>`, `rbd_check.py --write-vectors`. Review the diff, run the manual scan, then run the matching check against the new files before committing.
