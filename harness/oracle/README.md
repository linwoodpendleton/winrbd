# harness/oracle/

Command-line tools that print the core's answers about OSD maps and object placement in the format of Ceph's own tools, so a
script can diff the two. Built by the harness CMake from every `oracle/*.c` (no edit needed to add one; a file named `*_fmt.c`
holds helpers shared by the tools and is linked into each of them), linked against `wr_core_internal`; none of them opens a socket.

## wr-maporacle

Module `oracle-cli` (docs/design/core-architecture.md 18.4). One program, four modes (the three first need `--map`, the last
`--crush`):

| Mode | Prints | Compared with |
|---|---|---|
| `--map F --pool NAME --object HEX [--ns HEX] [--key HEX]` | `osdmap eN pool 'P' (id) object 'O' -> pg ID.HASH (ID.MASKED) -> up ([..], pN) acting ([..], pN)` | `ceph osd map` |
| `--map F --pool NAME... --names FILE` | the same line for every line of FILE: `<pool> <object hex or -> [<namespace hex or -> [<key hex or ->]]` | `ceph osd map -f json`, once per name |
| `--map F --pool NAME... --dump-pgs` | one line per PG: `ID.S raw ([..], pN) up ([..], pN) acting ([..], pN)` | `osdmaptool --test-map-pgs-dump-all` |
| `--map F --apply-inc F... [--epoch N] --pool NAME... --dump-state` | the compact state of the base map and after each applied incremental (`== epoch N`, flags, per-OSD state / weight / affinity / address, tracked pools, the five pg tables, a CRC of the CRUSH region) | the monitor's own full map of that epoch, and `ceph osd dump` |
| `--crush F --rule N --num-rep R --min-x A --max-x B [--pool-id P] [--weight OSD W]...` | `CRUSH rule N x X [..]` lines | `crushtool --test --show-mappings` |

- **Inputs.** A map, a CRUSH map or an incremental is a file with raw bytes (what `ceph osd getmap` / `getcrushmap` write) or hex text
  (lines with `#` comments, as in `harness/vectors/`); the tool tells them apart. `--apply-inc F` takes a file of lines `<epoch> <hex>` (the
  layout of `incrementals.hex`; an epoch is plain decimal, at most ten digits, no leading zero, so a hex dump written `08 07 ..` is read as one
  incremental) or one incremental. Incrementals up to the held epoch are skipped, the chain stops after `--epoch N`, an
  incremental that cannot be applied stops the run (exit 1) naming its epoch and the status, as a client would ask for a full map there.
  `--epoch N` ends the chain for good: nothing after the first incremental above N is applied, not even from a later file.
- **Pools** are tracked by name (`--pool`, at most eight: the core keeps only the pools it is told about, architecture 15) and listed in
  ascending pool id like `osdmaptool`.
- **Object bytes are hex** (`--object`, `--ns`, `--key`), so the exact bytes reach the hash; `--object-str`, `--ns-str` and `--key-str`
  take text. `-` or an empty string is the empty value. The namespace is hashed as `<ns> 0x1f <name>` and shown as `ns/name`, like
  `ceph osd map`; a locator key replaces the name in the hash. In the printed line bytes that are not printable ASCII, and the backslash,
  are written `\xHH` and `\\`: the one departure from Ceph's tools, which print raw bytes; the comparison scripts read fields, not names.
- **CRUSH mode** follows `crushtool`: `--pool-id P` maps x through `hash2(x, P)` first; every device a bucket holds weighs 1.0 and any
  other 0 unless `--weight` says (a number from 0 to 1, scaled by 0x10000 and truncated, clamped); the `choose_args` set is key 0, else
  the default key -1 (`--pool-id` does not select a set there, as in `crushtool`).
- **Limits.** `--slot-bytes` (default 8 MiB), `--max-osd` (65,536), `--work-max` (4,000,000 bucket draws per mapping), `--max-pgs` (4,194,304: `--dump-pgs` refuses a pool above it before printing anything, a damaged map can claim any `pg_num`), `--no-crc` (do not
  verify map CRCs). `--crush` and `--map` are two modes and cannot be mixed (exit 2). In CRUSH mode the file is at most 32 MiB and a map that
  names a device id above 16,777,216 is refused (the weight array is sized by the highest id a bucket holds, which a damaged map chooses). The tool allocates two map slots and one workspace with `malloc`; the core itself allocates nothing.
- **Exit status.** 0 every line answered; 1 a fatal problem (unreadable or damaged input, an incremental that cannot be applied, an absent
  pool for `--dump-pgs`; a message on stderr); 2 a usage error; 3 the run finished but some line is an `ERROR` line.
- **ERROR lines.** A request the core cannot answer is printed with `ERROR <status name>` in place of the sets (`osdmap e.. object '..' -> ERROR
  WR_E_..`, `P.S ERROR ..`, `pool P ERROR ..`, `CRUSH rule R x X ERROR ..`). `WR_E_POOL_UNSUPPORTED`, `WR_E_CRUSH_UNSUPPORTED` and
  `WR_E_CRUSH_NO_RULE` mean a pool or rule this client does not serve (erasure pools, tiers, indep rules, tree buckets); the comparison
  scripts count those as skipped, never as a pass. `WR_E_TOOBIG` is the core's limit of 4,096 bytes of name plus namespace plus key
  (`wri_place.h`): Ceph still hashes a longer name, so the vectors have rows (name of 4,096 bytes with a namespace) that only the core refuses.

Examples:

```sh
wr-maporacle --map full.bin --pool winrbd --object-str rbd_directory
wr-maporacle --map full.bin --pool winrbd --dump-pgs > ours.txt && osdmaptool full.bin --test-map-pgs-dump-all --pool 2 | diff - ours.txt
wr-maporacle --map base.hex --apply-inc incrementals.hex --epoch 709 --pool winrbd --dump-state
wr-maporacle --crush crush.bin --rule 1 --num-rep 3 --min-x 0 --max-x 9999 --pool-id 2
```

## Tests and scripts

| What | How |
|---|---|
| `harness/test/test_oracle_cli.c` (ctest `oracle.cli`) | runs the built tool on the committed vectors and compares its output byte for byte with the text the Ceph tools printed (`public/gt`: 8 `crushtool` runs of 10,000 mappings, the PG lines of `osdmaptool` for two pools, the `ceph osd map` lines) and with the committed JSON tables rendered into the same text (the 3,352 names of epoch 709, every state of `public/mapb`, the offline OSD maps, the offline CRUSH runs); also the escaping, the locator key, the batch file, the exit statuses and the damaged-input errors (a CRUSH map and an OSD map cut at many places, flipped bytes, bad numbers, cut and garbled incrementals, odd batch files) |
| `harness/tools/map_oracle_diff.py` | the comparison code (python3 standard library only): names, PG tables, CRUSH lines, state dumps (chain against full map, and against `ceph osd dump`), and `selftest`, which runs every committed vector through the tool and then damages the output in ten ways that each must be reported |
| `harness/tools/map_oracle_lab.sh --selftest` (ctest `oracle.selftest`) | the above without a cluster |
| `harness/tools/map_oracle_lab.sh run` | the live comparison on the lab VM; see the header of the script. Drives each state of architecture 18.3 (`wrtest-or-*` pools only), saves the map after each change, compares the name oracle once per pool geometry, every PG of every pool of every state, `crushtool` on the lab's CRUSH maps and on offline `--build` maps, and the chain of incrementals read from a copy of the monitor store against the monitor's full maps; restores the cluster and verifies the restore against a baseline; fails when nothing was compared or more was skipped (pools and rules this client does not serve) than compared |
