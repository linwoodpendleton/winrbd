<!-- SPDX-License-Identifier: MIT -->
# Handoff table (rBFT) test vectors

Golden vectors of the version 1 handoff table described in [docs/design/handoff-table.md](../../../docs/design/handoff-table.md).

| File | What it holds |
| --- | --- |
| `handoff-v1.json` | `valid`: eight described tables (typical IPv4, with the key, legacy key, eight IPv6 monitors, every flag, minimal, UTF-8 names, the 1,024-byte maximum) with the exact `body` and whole `table` bytes (hex). `refuse_decode`: damaged tables and bodies with the status the decoder must return, one defect each, checksum fixed up where the defect is not the checksum. `refuse_encode`: descriptions the encoder must refuse, with the status. |
| `gen_handoff_vectors.py` | The generator. A second, independent implementation of the layout (`struct.pack_into` at absolute offsets, no code shared with `core/src/handoff/`). Also writes the fuzz seeds. |

Provenance: generated, not captured. The keys in the vectors are fixed fake byte patterns (`(i * 37 + seed) & 0xff`), they are keys of nothing. The addresses are `10.77.0.x` (lab range) and `fd00:77::/64`.

Regenerate and check:

```sh
python3 -I harness/vectors/handoff/gen_handoff_vectors.py                  # rewrite handoff-v1.json
python3 -I harness/vectors/handoff/gen_handoff_vectors.py --check          # exit 1 when it is stale (also ctest handoff.vectors_in_sync)
python3 -I harness/vectors/handoff/gen_handoff_vectors.py --seeds harness/fuzz/seeds/fuzz_handoff   # also rewrite the fuzz seeds
```

Used by `harness/test/test_handoff_vec.c` (ctest `handoff.vec`) and, as seeds, by `harness/fuzz/fuzz_handoff.c`.
