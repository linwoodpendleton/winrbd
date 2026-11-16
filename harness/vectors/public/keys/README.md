# Public test keys

These are the keyrings of two throwaway cephx users that existed only on a private, disposable lab cluster
(Ceph v20.2.5, fsid `52762725-e19a-11f1-886d-525400770001`). **Both users were deleted from that cluster right
after the captures were taken**, so the keys authenticate nothing anywhere. **Never use them anywhere.**

Public test keys of users that were deleted from a private disposable lab cluster; never use them anywhere.

| File | Entity | Key type | Purpose |
|---|---|---|---|
| `client.vec-k2.keyring` | `client.vec-k2` | `aes256k` (cephx key type 2, 32-byte secret, the cluster default) | the key the `k2-*` captures were made with |
| `client.vec-k1.keyring` | `client.vec-k1` | `aes` (cephx key type 1, 16-byte secret, legacy) | the key the `k1-*` captures were made with |
| `wrong.vec-k2.keyring` | `client.vec-k2` | `aes256k` | random secret of the right type, never registered anywhere; used by `k2-wrongkey` |
| `wrong.vec-k1.keyring` | `client.vec-k1` | `aes` | random secret of the right type, never registered anywhere; used by `k1-wrongkey` |

Both real users had the same caps as the lab's regular RBD user: `mon 'profile rbd'`, `osd 'profile rbd pool=winrbd'`.

Why publish them: a decoder that checks the cephx proofs, the ticket and authorizer blobs and the secure-mode frames
needs the key to recompute them; with these keys anyone can verify the captures in `../pcap/` byte for byte.

## Deletion record

- Created: 2026-11-16, about 11:13 UTC (a first interrupted-run check found neither user present) (`ceph auth get-or-create`; `client.vec-k1` with `--key_type aes`).
- Last capture ended: 2026-11-16T11:33:19Z.
- **Deleted: 2026-11-16T11:38:59Z** (`ceph auth rm client.vec-k1`, `ceph auth rm client.vec-k2`, both exit code 0).
- Proof, run right after the deletion: `ceph auth get client.vec-k1` and `ceph auth get client.vec-k2` both fail with
  `Error ENOENT: failed to find client.vec-k1 in keyring` (resp. `client.vec-k2`), exit code 2.
- Nothing else of the lab's key store was touched: the entity and caps list (`ceph auth ls`) after the run is
  identical to the one taken before it (see `../baseline/revert-proof.txt`).
