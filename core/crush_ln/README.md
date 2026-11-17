# core/crush_ln/

The one directory of `core/` that is **not** MIT. It holds the two fixed-point logarithm tables that CRUSH
straw2 needs to place data bit-for-bit like Ceph, and nothing else of CRUSH. See "The CRUSH log table exception"
in [`LICENSE`](../../LICENSE) for why, and `docs/design/core-architecture.md` section 16.2 for how the rest of the
core meets this directory.

| File | What | License |
|---|---|---|
| `crush_ln_table.h` | `__RH_LH_tbl` (258 entries) and `__LL_tbl` (256 entries), **copied unchanged** from Ceph v20.2.5 `src/crush/crush_ln_table.h` (commit `ed27c686770872022f4c1de04f6b0ac5d5384ded`), with its original copyright and licence notice (Copyright (C) 2015 Intel Corporation, GNU LGPL version 2.1). SHA-256 `9d0cdacacbb4a21da36f134368e41e835fca1d5d6058e6abebb85775339e1b1a`, 12,506 bytes. | LGPL-2.1-only (`crush_ln_table.h.license`) |
| `crush_ln_table.h.license` | the SPDX tag of the file above (a sidecar, so the copied file stays byte-identical) | |
| `crush_compat.h` | our own 20-line stand-in for the Ceph header of the same name that the table header includes: it defines `__s64` as `const int64_t`, so the tables land in read-only data (the core has no writable globals) | LGPL-2.1-only |
| `wri_crush_lntab.c` | two accessors, `wri_crush_ln_rh_lh()` and `wri_crush_ln_ll()`, that return the tables | LGPL-2.1-only |

Rules:

- `crush_ln_table.h` is never edited. The test `map.skel` checks its SHA-256 against the value above (and `core.docs`
  checks that the directory holds exactly these files); to update it, copy the new Ceph file again and change the digest
  in the same commit.
- Nothing else goes here: not the arithmetic that uses the tables (that is `core/src/crush/wri_crush_ln.c`, MIT, written
  from `docs/spec/crush-and-placement.md` 3.4.2), not hashes, not bucket code. The boundary is these four files.
- Every file here carries `SPDX-License-Identifier: LGPL-2.1-only` (directly, or through the `.license` sidecar).
  `core/sources.txt` lists `wri_crush_lntab.c`; the iPXE glue tags that object `GPL2_OR_LATER` (`WR_FILE_LICENCE_LGPL21`),
  the Windows driver is LGPL already, the Linux harness links it as any other object of the core.
