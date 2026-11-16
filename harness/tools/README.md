# harness/tools: Phase 0 checkers

<!-- SPDX-License-Identifier: MIT -->

Independent checkers for the protocol notes in [docs/spec/](../../docs/spec/README.md). Each one was written from its note alone (no Ceph decoder, no Ceph code), parses real packet captures and tool output, and fails if the note and the bytes disagree. They also write and verify the scrubbed test vectors in [../vectors/](../vectors/).

License: MIT. Every file carries `SPDX-License-Identifier: MIT`.

## Quick start

From a fresh clone, with Python 3, the `cryptography` package and `curl` (nothing else: no Ceph, no cluster, no other directory next to the checkout):

```sh
harness/tools/run-all.sh
```

It (1) runs `fetch-ceph-ref.sh`, which downloads the few Ceph files the checkers read at run time into `harness/.ceph-ref/` (git-ignored; skipped when already complete), (2) runs all eight checkers on the public vector set in `harness/vectors/public/` with the public throw-away keys in `harness/vectors/public/keys/`, and (3) prints a table of passed / failed / skipped checks, then every skipped check with its reason. It exits non-zero if anything failed. A skip is a check whose input the public set does not contain; it is never counted as a pass or as a failure. Options: `-v` (print every checker's full output), `--serial` (one checker at a time; the default runs all eight in parallel, about a minute and a half on a laptop).

Every checker also runs alone with no arguments, for example `python3 harness/tools/msgr2_check.py`. The defaults are:

| What | Default | Override |
|---|---|---|
| capture set | `harness/vectors/public` | `--captures <dir>` |
| cephx keys | `harness/vectors/public/keys` (only that directory) | `--keys <dir>` (`--secrets` for `monclient_check.py`) |
| Ceph run-time data | `$WINRBD_CEPH_SRC`, else `harness/.ceph-ref` | `--ceph-src <dir>` (alias `--ref`) for `osdmap_check.py` and `crush_check.py` |

All paths are resolved from the script's own location, not from the current directory.

## What is here

| Tool | Checks note | Vectors | Captures (default: the public set) |
|---|---|---|---|
| `msgr2_check.py` | [msgr2.md](../../docs/spec/msgr2.md) | `vectors/msgr2/` | yes; `--check-vectors <dir>` alone checks only the vectors |
| `secure_check.py` | [msgr2-secure-mode.md](../../docs/spec/msgr2-secure-mode.md) | `vectors/secure/` | yes |
| `cephx_check.py` | [cephx.md](../../docs/spec/cephx.md) | `vectors/cephx/` | yes; `--vectors <dir>` alone checks only the vectors |
| `monclient_check.py` | [mon-client.md](../../docs/spec/mon-client.md) | `vectors/monclient/` | yes |
| `osdmap_check.py` | [osdmap.md](../../docs/spec/osdmap.md) | `vectors/osdmap/` | yes; `--vectors-only` checks only the vectors |
| `crush_check.py` | [crush-and-placement.md](../../docs/spec/crush-and-placement.md) | `vectors/crush/` | yes |
| `osdop_check.py` | [osd-ops.md](../../docs/spec/osd-ops.md) | `vectors/osdop/` | yes; `--vectors-only` checks only the vectors |
| `rbd_check.py` | [rbd-format2.md](../../docs/spec/rbd-format2.md) | `vectors/rbd/` | yes; `--vectors-only` checks only the vectors |
| `run-all.sh` | (runs the eight checkers above and prints the summary) | | |
| `fetch-ceph-ref.sh` | (downloads the Ceph run-time data, see below) | | |
| `pubset.py` | (shared defaults: public set, keys, Ceph data directory; the result lines `run-all.sh` reads) | | |
| `wire.py` | (shared helpers: CRC-32C, reader, pcap and TCP reassembly, msgr2 and cephx primitives) | | |
| `msgr2_probe.py` | (live probe, see below) | | no, needs a lab monitor |

The other checkers carry their own helpers; only `monclient_check.py` imports `wire.py`, and all of them import `pubset.py`. Each vector directory has a README on provenance, scrubbing and how its files are regenerated.

Every checker prints, last, `WINRBD-SKIP` lines (one per skipped check, with the reason) and one `WINRBD-RESULT tool=... passed=... failed=... skipped=...` line; `run-all.sh` builds its table from them.

## Requirements

- Python 3 (run with 3.14.6 locally and 3.12 in CI) and the `cryptography` package (run with 46.0.3 locally and 44.0.2 in CI). Nothing else: no Ceph installation, no root.
- `curl` and network access to `raw.githubusercontent.com`, once, for `fetch-ceph-ref.sh`. Without it `osdmap_check.py` skips the checks that need the Ceph data and `crush_check.py` cannot run (`run-all.sh` reports that as a failure).
- The checkers only read. They write nothing unless you pass an explicit `--emit-vectors` / `--write-vectors` / `--export-vectors` option. `run-all.sh` sets `PYTHONDONTWRITEBYTECODE=1` so that no `__pycache__` appears in the working tree; set it yourself when running a checker directly.
- Run them as scripts (`python3 harness/tools/<name>.py ...`); the current directory does not matter.
- Keys are read at run time from `harness/vectors/public/keys/` and are never printed.

## The public vector set, and the private one

The default input is [`../vectors/public/`](../vectors/public/MANIFEST.md): 22 pcaps of a stock Ceph 20.2.5 client against a disposable lab cluster, the ground-truth files the Ceph tools printed for it, and the two throw-away cephx keys the sessions used (published on purpose: both users were deleted from the cluster right after the captures, see [`../vectors/public/keys/README.md`](../vectors/public/keys/README.md)). It is small (about 23 MB) and contains no key, session secret or debug log of any real cluster.

The first, larger Phase 0 set (39 pcaps, with session secrets and debug logs) is private lab material, kept by the maintainers outside this repository, and must never be added to it (see [CONTRIBUTING.md](../../CONTRIBUTING.md), rule 4). The checkers can still run on such a set with `--captures <dir> [--keys <dir>]`; for any capture set other than the public one the key directories fall back to the old layout (`<captures>/../lab-secrets` and `<captures>/secrets/keys`), and `--ceph-src` points at a Ceph source tree at the pinned commit if you have one:

```
<parent>/winrbd/                        this repository
<parent>/winrbd-ref/captures/           a private capture set; mode 0700
    pcap/  sessions.tsv  gt*/ data/ logs/ stdout/ MANIFEST.md
    secrets/                            session secrets and full debug logs; mode 0700
<parent>/winrbd-ref/lab-secrets/        its keyrings; mode 0700
```

### What the public set cannot show (reported as skips)

A check whose input is not in the public set is reported as `SKIP <name>: <reason>`, counted in the summary, and never fails the run. With the current set that is:

- the checks that compare the keys a checker derives from the wire with the stock client's own `debug_auth` log (`msgr2_check.py` AUT-11, `secure_check.py` log claim, `cephx_check.py` log cross-check): the logs print session keys and are not published; every ticket is still decrypted from the wire and cross-checked against the other frames;
- `msgr2_check.py` NEG-2 and one `rbd_check.py` check: they need a session by a read-only cephx user (EPERM replies), which the public set does not contain;
- one `rbd_check.py` check: the librbd exclusive-lock acquire needs a write session on a default-feature image; the public bench writes to a layering-only image;
- `osdmap_check.py` and `crush_check.py`: the "equals the stored map of its epoch" comparison. `gt/osdmap.bin` is epoch 141 and the stored full maps in `gt3/` cover epochs 1 to 89 only; the same map is compared byte for byte with `baseline/baseline-after/osdmap.bin` instead (a real check, not a skip).

Checks that depend on the size of the workload (the `rbd bench` shape, the minimum number of CALL ops) are parameterised from the session's own command line (`cmd/<session>.cmd`) and a minimum count, so the compact set is checked as strictly as the large one.

## Running everything

```sh
harness/tools/run-all.sh          # fetch (if needed), run the eight checkers, print the summary
```

or one at a time, all with the defaults described in the quick start:

```sh
export PYTHONDONTWRITEBYTECODE=1
sh      harness/tools/fetch-ceph-ref.sh      # once; osdmap_check.py and crush_check.py need it

python3 harness/tools/msgr2_check.py
python3 harness/tools/secure_check.py
python3 harness/tools/cephx_check.py
python3 harness/tools/monclient_check.py
python3 harness/tools/osdmap_check.py
python3 harness/tools/crush_check.py
python3 harness/tools/osdop_check.py
python3 harness/tools/rbd_check.py
```

The checkers are independent; `run-all.sh` runs them in parallel. Every one exits 0 when all checks pass and non-zero when any check fails. Lines starting with `WARNING`, `note[...]` or `info` are not failures. Some `k1-*` captures contain one duplicated TCP segment (identical bytes, nothing missing); the decoders tolerate that, see section 4 of the [manifest](../vectors/public/MANIFEST.md).

Without any capture set, the committed vectors can still be verified:

```sh
python3 harness/tools/msgr2_check.py --check-vectors harness/vectors/msgr2
python3 harness/tools/cephx_check.py --vectors harness/vectors/cephx
python3 harness/tools/osdop_check.py --vectors-only
python3 harness/tools/rbd_check.py   --vectors-only
python3 harness/tools/osdmap_check.py --vectors-only          # vectors and self-tests only
```

`crush_check.py` has two speed options: `--quick` (skip large-segment CRCs and the in-tree group) and `--tree-x N` (how many inputs per in-tree known-answer file; default 8, 1024 means whole files and takes minutes).

### Continuous integration

[`.github/workflows/vectors.yml`](../../.github/workflows/vectors.yml) runs `harness/tools/run-all.sh` on every push and pull request (ubuntu-latest, Python 3.12, a pinned `cryptography`, the Ceph run-time data cached by commit).

### Reference runs

Public set (22 pcaps), 2026-11-16, `harness/tools/run-all.sh`, every checker exit 0:

| Tool | Passed | Failed | Skipped |
|---|---|---|---|
| `msgr2_check.py` | 77,514 | 0 | 2 |
| `secure_check.py` | 69,676 | 0 | 1 |
| `cephx_check.py` | 38,793 (37,839 on captures, 954 on vectors) | 0 | 1 |
| `monclient_check.py` | 193 named checks (35,949 assertions) | 0 | 0 |
| `osdmap_check.py` | 119 | 0 | 1 |
| `crush_check.py` | 81 (about 612,000 comparisons) | 0 | 1 |
| `osdop_check.py` | 33,739 | 0 | 0 |
| `rbd_check.py` | 1,849 | 0 | 2 |

The unit of "passed" differs per checker (checks, assertions or named checks); compare a checker only with its own earlier runs.

Private Phase 0 set (39 pcaps), same day, every one exit 0:

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

In that set the captures `k1-rbd-bench-default` and `k1-sec-rados-big` lost packets on the 9 MiB transfers (tcpdump kernel drops), and the checkers analyse those streams only up to the hole and say so.

Offline vector runs: msgr2 68 passed, cephx all passed, osdop 219 passed, rbd 172 passed, osdmap 52 passed (self-tests and vectors).

## Live probe: `msgr2_probe.py`

A small msgr2 / cephx client that sends deliberately unusual frames to one monitor to settle questions a stock client cannot answer (banner variants, alignments, message flags, duplicate sequence numbers, feature-bit masks). It is the only tool here that opens a network connection.

- Point it only at a lab cluster you own and can afford to break: some experiments make the monitor close the connection, and the notes record one (non-power-of-two alignment) that was deliberately not tried because it could crash the only monitor.
- Needs a keyring (`--keyring`) and the monitor address (`--mon`, default `10.77.0.10:3300`, the lab default); `--entity` defaults to `client.winrbd`.
- The results it produced are written up in `docs/spec/msgr2.md` (section 6) and `harness/vectors/msgr2/README.md`.

## Licensing rule for Ceph data (run-time loading only)

- The tools and the vectors are our own work, MIT. They contain no Ceph source, comments or lookup tables.
- A check that needs data which exists only in Ceph's sources loads it at run time and never embeds it. The CRUSH fixed-point log tables (`RH_LH`, `LL_tbl`) are parsed from `<ceph-src>/src/crush/crush_ln_table.h` when `osdmap_check.py` or `crush_check.py` run (`--ceph-src <dir>`, else `$WINRBD_CEPH_SRC`, else `harness/.ceph-ref`); without the file `osdmap_check.py` reports those checks as skipped and `crush_check.py` fails the groups that need them (it cannot run them). The vectors carry only computed outputs (a handful of `crush_ln` results), never the tables. This keeps licensing question L1 in [docs/spec/README.md](../../docs/spec/README.md) section 8 open without the repository depending on its answer.
- The same holds for Ceph's test inputs: the in-tree CRUSH known-answer files (`src/test/cli/crushtool/`, `crush_check.py` group F) are read from `<ceph-src>` at run time and never copied here; cephx type-2 vectors come from RFC 8009, typed from the RFC.
- `fetch-ceph-ref.sh` is how a fresh clone gets those files: it downloads exactly 17 files from `https://raw.githubusercontent.com/ceph/ceph/ed27c686770872022f4c1de04f6b0ac5d5384ded/<path>` (the pinned v20.2.5 commit) into `harness/.ceph-ref/<path>`, and compares every file with a sha256 kept in the script (a mismatch deletes the file and fails). It prints a notice that the files are Ceph's (mostly LGPL-2.1) and not part of winrbd. `harness/.ceph-ref/` is listed in `.gitignore`; never commit it. A Ceph source tree at the same commit works too: `--ceph-src <tree>` or `WINRBD_CEPH_SRC=<tree>`. To change the file list, update `FILES` in the script together with the hashes (`sha256` of the file at the pinned commit).
- Ceph tools (`ceph`, `rbd`, `rados`, `crushtool`, `osdmaptool`, `ceph-dencoder`, `ceph-monstore-tool`) are used only as oracles in the lab; what lands in the capture directory is their output. Do not run them from this repository, and do not decode with them inside a checker.
- A tool that links, compiles or imports Ceph code (oracle helpers built from the reference C files, for example) lives under `<parent>/winrbd-ref/tools/`, never in this repository, and its output code is never copied in.

## Secrets rule

- Raw captures, keyrings, `debug_auth` logs, session keys, tickets, connection secrets and decrypted authentication payloads of any real cluster or user stay private (mode 0700). The one exception is the public set in `harness/vectors/public/`: it holds only the keys of throw-away users that were deleted from the cluster right after the captures, no debug logs and no session-secret files, and it was scanned against every key and session key of the private set (0 hits).
- A vector is committed only if it is scrubbed: key material, key-derived nonces, tickets, signatures and encrypted blobs are replaced by labelled placeholders of the same length, or only structure (lengths, offsets) is kept. The scrubbing of each vector directory is explained in its README.
- The `--emit-vectors` options of the writers run a leak guard (`msgr2_check.py` compares its output with every key and session key known to the capture set and deletes the files on a hit). There is no single repository-wide scrub script yet.
- Allow-list for scans: the four `harness/vectors/cephx/session-*.json` files contain a `keyring_key_base64` that looks like a cephx key. These are **synthetic** (derived from public labels by `cephx_check.py`), not lab keys; a scan that flags them is right to ask and the answer is in the file's `description`. The four keyrings in `harness/vectors/public/keys/` are real cephx-format keys of users that no longer exist (see that directory's README); the pcaps in `harness/vectors/public/pcap/` and the files under `gt*/` contain tickets and key-derived bytes of sessions made with them.

### Manual scan before committing or publishing

Run from the repository root; each command should print nothing, apart from the allow-listed hits noted:

```sh
# keyring lines
grep -rIn --exclude-dir=.git --exclude-dir=third_party -E '^\s*key\s*=\s*\S+' . | grep -v '\.py:'
# base64 strings of cephx key length (40 chars starting AQ, 60 chars starting Ag) or any long base64 with padding
grep -rIn --exclude-dir=.git --exclude-dir=third_party -E 'AQ[A-Za-z0-9+/]{30,}|Ag[A-Za-z0-9+/]{50,}|[A-Za-z0-9+/]{38,}={1,2}' .      # allowed: the four cephx session-*.json (synthetic)
# addresses: only the lab ranges 10.77.0.x and 10.78.0.x, documentation ranges and loopback may appear
grep -rIhoE --exclude-dir=.git --exclude-dir=third_party '\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b' . | sort | uniq -c | sort -rn
# names that must not appear in repository files
grep -rIniE --exclude-dir=.git --exclude-dir=third_party '/Users/|/home/[a-z]|@[a-z0-9-]+\.(com|net|org|io|cn)' .
```

A stronger check compares the repository with every secret the private capture sets know: collect every base64 and 32+ hex token from their `lab-secrets` and `captures/secrets` directories, derive their raw and hex forms, and search the repository for each. The scan used before the Phase 0 publication did exactly this over 2,417 candidates and found 0 hits (and it does find them when pointed at the raw log directory, which proves it can see). The cluster fsid and the lab monitor name appear in two `monclient` vectors; they are not secrets.

## Regenerating vectors

The public set is regenerated with `harness/vectors/public/scripts/` (see its [manifest](../vectors/public/MANIFEST.md), section 9); it needs a disposable Ceph lab. For the committed vectors, each vector directory's README gives the exact command. In short: `msgr2_check.py --emit-vectors <dir>`, `secure_check.py --export-vectors <dir>`, `cephx_check.py --emit-vectors <dir>`, `monclient_check.py --write-vectors <dir>`, `osdmap_check.py --write-vectors`, `crush_check.py --emit-vectors <dir>`, `osdop_check.py --emit-vectors <dir>`, `rbd_check.py --write-vectors`. Review the diff, run the manual scan, then run the matching check against the new files before committing.
