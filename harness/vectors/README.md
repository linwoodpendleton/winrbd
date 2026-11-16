# harness/vectors: test vectors and the public capture set

<!-- SPDX-License-Identifier: MIT -->

Everything the checkers in [../tools/](../tools/README.md) verify the protocol notes in [docs/spec/](../../docs/spec/README.md) against. Two kinds of data live here.

## Quick start: verify the notes yourself

From a fresh clone, with Python 3, the `cryptography` package and `curl`:

```sh
harness/tools/run-all.sh
```

This downloads the few Ceph files the checkers read at run time (pinned Ceph commit, sha256-checked, into the git-ignored `harness/.ceph-ref/`; they are never part of this repository), runs all eight checkers on the public set below and prints a table of passed, failed and skipped checks. It exits non-zero if any check failed. Nothing else is needed: no Ceph, no cluster, no lab access, no other directory next to the checkout.

## The public capture set: `public/`

Real bytes, so that anyone can verify the notes and develop against them. See [public/MANIFEST.md](public/MANIFEST.md) for the full description.

- 22 packet captures (`public/pcap/`) of a stock Ceph 20.2.5 client (`rbd`, `rados`, `ceph`, a python `rados` client) against a disposable lab cluster: image info, small and large object I/O, `rbd bench`, map download, idle keepalives and ticket renewal, forced secure mode, default options, and wrong-key attempts. Each session was made once with a modern (`aes256k`) and once with a legacy (`aes`) cephx key.
- The ground truth the Ceph tools printed for the same cluster state (`gt/`, `gt2/` .. `gt5/`, `baseline/`): maps, CRUSH, placement answers, RBD metadata. The Ceph tools appear only as the expected answer; the checkers never run them.
- Two throw-away cephx keys (`public/keys/`). **Publishing them is safe on purpose:** both users existed only on the disposable lab cluster and were deleted from it right after the captures were taken (the deletion record and proof are in [public/keys/README.md](public/keys/README.md) and `public/baseline/revert-proof.txt`). They authenticate nothing anywhere. The keys of any real cluster, session secrets and client debug logs are not part of this set, and the set was scanned against every known key and session key (0 hits).

What the public set does not contain is reported by the checkers as `SKIP` with a reason (never as a pass); see "What the public set cannot show" in [../tools/README.md](../tools/README.md).

## The committed vectors: one directory per checker

Small, scrubbed, self-contained files that a decoder can use as known-answer tests without any capture. Each directory has its own README (provenance, what was scrubbed, how it is regenerated).

| Directory | Checker | Content |
|---|---|---|
| [msgr2/](msgr2/README.md) | `msgr2_check.py` | CRC-32C, frame layouts (crc mode and secure mode), handshake skeletons, pre-auth HMAC |
| [secure/](secure/README.md) | `secure_check.py` | secure-mode primitives, frame vectors, connection-secret and signature structure |
| [cephx/](cephx/README.md) | `cephx_check.py` | cipher types 1 and 2, RFC 8009 vectors, challenge proof, session keys, scrubbed frames |
| [monclient/](monclient/README.md) | `monclient_check.py` | monitor client messages (subscribe, monmap, osdmap, renewal, keepalive) and scenarios |
| [osdmap/](osdmap/README.md) | `osdmap_check.py` | a full OSDMap, incrementals, embedded CRUSH blob, placement answers |
| [crush/](crush/README.md) | `crush_check.py` | CRUSH blob, hashes, placement inputs and expected outputs |
| [osdop/](osdop/README.md) | `osdop_check.py` | OSD request / reply messages for the operations a client sends |
| [rbd/](rbd/README.md) | `rbd_check.py` | RBD header omap, class-method calls, striping and object names |

Each checker verifies its own directory automatically when it runs; `--vectors-only` / `--check-vectors` (where offered) runs only that part and needs no capture set.

## Rules for adding data here

- No keys, keyrings, tickets, session secrets, connection secrets or debug logs of a real cluster or user (see [CONTRIBUTING.md](../../CONTRIBUTING.md), rule 4). The only keys allowed are those of throw-away users that were deleted from the cluster right after capturing and whose deletion is recorded next to them, as in `public/keys/`.
- No Ceph source, tables or test files. Data that exists only in Ceph's sources (the CRUSH log tables, the in-tree crushtool known-answer tests) is fetched at run time by `harness/tools/fetch-ceph-ref.sh` and is not stored here.
- No internal addresses or user names; the lab ranges 10.77.0.x and 10.78.0.x are fine.
- Run `harness/tools/run-all.sh` and the manual scan in [../tools/README.md](../tools/README.md) before sending a change.
