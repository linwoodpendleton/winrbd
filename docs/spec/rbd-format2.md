# Spec note: RBD format 2 image access (header metadata, naming, striping, sparse I/O, exclusive lock), client side

Status: draft, derived from reading the pinned source, then checked against a live Ceph v20.2.5 cluster (2026-11-16) with an independent decoder, `harness/tools/rbd_check.py`, written from this note only. Items settled by a capture or by the stock tools' output are marked **[confirmed: evidence]**; wrong or incomplete statements were corrected in place and listed under "Corrections after capture" at the end of section 6. Items still marked **[confirm on capture]** or **[unverified]** could not be settled by the captures, and section 6 says why. Evidence names: `pcap/<session>` = the 39 crc/secure captures of the Phase 0 set, `probe-a` / `probe-b` = the extra probe captures (`rbd-extra/pcap/`), `gt4` = the lab ground truth dumps (`rbd info`, `rados listomapvals`, `rados exec`); the vectors are in `harness/vectors/rbd/`.

Reference tree: Ceph tag v20.2.5 (Tentacle), commit ed27c686770872022f4c1de04f6b0ac5d5384ded. All `path:line` references below are relative to that tree root unless stated otherwise. Everything is written from the point of view of a **client** that opens an existing image and does block I/O on it. Image creation, resize, snapshot management, clone, flatten, mirroring and trash handling are server-side or administrator-side operations and are out of scope except where they change what a reader or writer must do.

---

## 1. Scope and sources

### 1.1 What this note covers

- How a format-2 image is spread over RADOS objects, and the exact object names a client must build (id object, directory, header, data objects, object-map objects).
- Resolving an image name to an image id.
- Reading image metadata through the `rbd` object class (class name and method name, input bytes, output bytes) and through the `lock` object class: size and order, features, object prefix, snapshot context, data pool id, stripe unit and count, parent, flags, operation features, and the exclusive-lock / advisory-lock state.
- The feature bits, their numeric values, which of them make an image unusable for a client that does not implement them, and which of them a v1 client should accept.
- The mapping from an image byte range to object extents (default striping in full, the general formula as reference), and the sparse-read rules.
- The write path requirements: snapshot context on writes, implicit object creation, discard / zero mapping.
- What the exclusive-lock feature means for a writer that is not librbd, with the object-map, fast-diff and journaling features off.
- A proposed v1 image profile with exact feature values.

### 1.2 What this note does not cover

- The RADOS wire format: MOSDOp / MOSDOpReply encoding, how an op vector is framed, object locators and placement. See the MOSDOp note and the OSDMap / CRUSH notes in this directory. This note names the OSD ops that are needed and the payloads of the `call` op, and nothing else about them.
- msgr2 framing and authentication (`docs/spec/msgr2.md`, mon and cephx notes).
- Watch / notify on the header object (needed to be told about header changes, and to take part in the cooperative lock protocol). Only its consequences are described, see 3.8 and 3.9.
- RBD format 1 (images named `<name>.rbd`). Rejected, see 4.
- Layering (clones), object-map, fast-diff, journaling, mirroring, migration, groups, encryption and the trash: out of v1, only detected and refused.

### 1.3 Sources read

| Source | Used for |
|---|---|
| `src/include/rbd_types.h` | object name prefixes, constant names, id / prefix length limits |
| `src/include/rbd/features.h` | feature bit values, the incompatible / read-write-incompatible / mutable masks, operation-feature bits |
| `src/librbd/Utils.cc`, `src/librbd/Utils.h` | id object and header object name builders, id generation, data object name builder |
| `src/librbd/Types.h` | parent info, open flags, read-only flags (names only) |
| `src/librbd/image/OpenRequest.cc` | the exact sequence of metadata calls a client issues at open |
| `src/librbd/image/RefreshRequest.cc` | the mutable-metadata compound read, compatibility checks, parent / op-feature / snapshot reads, when the exclusive lock and object map are opened |
| `src/librbd/image/CreateRequest.cc` | how the object prefix, striping feature and layout are chosen at creation (to know what a reader will see) |
| `src/librbd/ImageCtx.cc` | layout initialisation, data IO context (snapshot context rules), discard granularity |
| `src/cls/rbd/cls_rbd.cc`, `cls_rbd_client.cc`, `cls_rbd.h`, `cls_rbd_types.h/.cc` | method names, input / output encodings, error returns, the omap keys of the header object |
| `src/cls/lock/*` | lock class methods, lock record layout, semantics of lockers, tag and expiry |
| `src/librbd/managed_lock/*`, `src/librbd/ManagedLock.cc`, `src/librbd/ExclusiveLock.cc`, `src/librbd/exclusive_lock/ImageDispatch.cc` | how librbd uses the lock: names, cookie and tag formats, break / blocklist rules, when a lock is required |
| `src/librbd/io/ObjectRequest.cc`, `ObjectRequest.h`, `ImageRequest.cc`, `Utils.cc`, `src/librbd/internal.cc` | per-object read / write / discard behaviour, clipping |
| `src/osdc/Striper.cc`, `src/include/fs_types.h` | striping math, object count, read assembly |
| `src/osd/PrimaryLogPG.cc`, `src/osd/osd_op_util.cc`, `src/osd/OSDCap.cc`, `src/osd/osd_types.cc` | how the OSD uses a client snapshot context, how the `call` op is classified, dispatched and permission-checked, read / write / zero / truncate / delete semantics, how the reply carries per-op output |
| `src/osdc/Objecter.h`, `src/librbd/io/ReadResult.cc` | exact op fields librbd fills, sparse-read reply layout, how a missing object becomes zeros |
| `src/common/snap_types.h/.cc`, `src/include/rados.h` | snapshot context encoding and validity, special snapshot ids, op code numbers |
| `src/common/options/rbd.yaml.in`, `osd.yaml.in` | defaults that decide what an existing image looks like and which limits apply |
| `doc/dev/rbd-layering.rst`, `doc/dev/file-striping.rst`, `doc/rbd/rbd-exclusive-locks.rst`, `doc/man/8/rbd.rst`, `doc/rados/operations/user-management.rst` | documented behaviour of layering, striping, locks, image-shared, OSD capability profiles |

The kernel RBD driver (krbd) is not in this tree. Everything said about krbd below comes from `doc/man/8/rbd.rst` and `doc/rbd/rbd-exclusive-locks.rst` and is marked accordingly.

### 1.4 Conventions

- All integers are little-endian. `u8/u32/u64/i64` mean unsigned or signed fixed-width integers.
- `string` = `u32 length` followed by `length` raw bytes, no terminator (`src/include/encoding.h:227-246`).
- `bool` = one byte, 0 or 1.
- `vector<T>` = `u32 count` followed by the elements back to back. `map<K,V>` = `u32 count` followed by key, value pairs.
- `optional<T>` = `u8 present` (0 or 1); if 1, followed by the `T` (`src/include/encoding.h:670-692`). `map<K,V>` and `vector<T>` of structs simply repeat the element encoding, so every struct element carries its own 6-byte header.
- Versioned struct ("struct header") = `u8 struct_v`, `u8 struct_compat`, `u32 struct_len`, then `struct_len` bytes of body (`src/include/encoding.h:1455-1463` for encode, `:1511-1523` for decode). A decoder rejects the struct if its own supported version is lower than `struct_compat`, rejects it if `struct_len` exceeds the bytes left, and may skip any unknown trailing bytes using `struct_len`. The `lock` class structs (2.7) are decoded with a legacy-compatible macro (`:1602-1621`) that behaves the same way for version 1, because they have always carried the header. Where this note says "skip by length" it means: read the 6-byte header, then advance `struct_len` bytes.
- `CEPH_NOSNAP` = `0xFFFFFFFFFFFFFFFE` (head, the live image), `CEPH_SNAPDIR` = `0xFFFFFFFFFFFFFFFF`, `CEPH_MAXSNAP` = `0xFFFFFFFFFFFFFFFD` (`src/include/rados.h:38-40`).
- Error numbers are written as Linux errno names. The OSD returns them negated in the reply result field. The numeric values on the wire are the Linux ones **[confirmed: probe-a (t4.* and t20.* steps), pcap/k2-rbd-create-rm, pcap/x-t0-ro: -1 EPERM, -2 ENOENT, -5 EIO, -8 ENOEXEC, -16 EBUSY, -17 EEXIST, -22 EINVAL, -95 EOPNOTSUPP]**; `EOLDSNAPC` and `EBLOCKLISTED` were not provoked and stay **[confirm on capture]**. Two Ceph-specific values: `EOLDSNAPC` = 85, `EBLOCKLISTED` = 108 (`src/include/rados.h:498-499`).
- "image id" and "image name" are different strings. The id is stable for the life of the image, the name can change.

---

## 2. Wire structures

### 2.1 Objects of one image

All of these live in the pool that holds the image metadata ("metadata pool"), and in the same RADOS namespace as the image (the default, empty namespace, in v1), except data objects, which live in the data pool (see 2.1.2).

| Object name | Content | Needed by a v1 client |
|---|---|---|
| `rbd_id.<name>` | The image id: the raw object data is one encoded `string` (u32 length + id bytes). | yes, to resolve name to id |
| `rbd_directory` | Pool-wide image directory. Omap keys `name_<name>` -> encoded string `<id>` and `id_<id>` -> encoded string `<name>`. | optional (fallback / listing) |
| `rbd_header.<id>` | All image metadata, as omap keys written by the `rbd` class (2.4). Also carries the lock record (xattr `lock.rbd_lock`, 2.7) and the watchers. | yes |
| `rbd_data.<id>.<objno>` | Data object (default layout). See 2.1.1 for the exact name rule. | yes |
| `rbd_object_map.<id>` and `rbd_object_map.<id>.<snapid>` | Object-map objects (head and per-snapshot). `<snapid>` is 16 lowercase hex digits, zero padded. | no, only to understand the name |
| `rbd_info` | Pool-level metadata. | no |
| `rbd_trash` | Pool-level trash list. | no |
| `rbd_children` | Pool-level clone relations. | no |

Sources: name prefixes `src/include/rbd_types.h:28-31,42-43,61,113`; builders `src/librbd/Utils.cc:51-59` (`rbd_id.` + name, `rbd_header.` + id); object-map name `src/librbd/ObjectMap.cc:59-70`; doc `doc/dev/rbd-layering.rst:162-180`. The directory omap keys are `name_<name>` and `id_<id>` (`src/cls/rbd/cls_rbd.cc:81-82`).

#### 2.1.1 Data object names

The name is built from the **object prefix stored in the header** (read with `get_object_prefix`, 2.3) plus a dot plus the object number as **16 lowercase hex digits, zero padded** (`src/librbd/ImageCtx.cc:239-246` for the format string, `src/librbd/Utils.h:155-166` for the formatting; object number is a u64). A client must use the stored prefix verbatim and must not rebuild it from the id.

How the prefix looks for images created by v20.2.5 librbd (`src/librbd/image/CreateRequest.cc:428-445`; the metadata pool id used is the one of the pool that holds the header, `:435-438`):

| Image | Prefix |
|---|---|
| data stored in the same pool as the metadata | `rbd_data.<id>` |
| data stored in a separate data pool (feature DATA_POOL) | `rbd_data.<metadata pool id as decimal>.<id>` |

A data pool image really has the metadata pool id in the prefix and its objects live in the data pool: `rbd_data.2.600ecac4b85c.0000000000000000` in pool `t0-data` (id 5), header requests stay in pool 2 **[confirmed: probe-a (writes carry oloc pool 5), gt `t0-data.ls`, rbd_check.py "librbd data path"]**. Examples: id `abc123`, object 2, same pool: `rbd_data.abc123.0000000000000002`. With metadata pool id 7: prefix `rbd_data.7.abc123`, object 255: `rbd_data.7.abc123.00000000000000ff`.

Limits: the full object name must stay below 96 bytes, that is at most 95 characters (`src/include/rbd_types.h:77`, assertion at `src/librbd/Utils.h:160`, which compares the length that `snprintf` would have produced); image creation refuses a prefix longer than 43 bytes (`src/librbd/image/CreateRequest.cc:436-442`, constant `src/include/rbd_types.h:97`). The figure of 14 bytes for an image id is only the length librbd truncates a **generated** id to (`src/librbd/Utils.cc:88-89`, constant `src/include/rbd_types.h:86`); no server-side method enforces it (`is_valid_id`, `src/cls/rbd/cls_rbd.cc:235-244`, checks only non-empty and alphanumeric, and is only called when an id is stored). A client must therefore **not** reject an id for being longer than 14 bytes; it must only require non-empty, alphanumeric (`isalnum`, ASCII) and that the names built from it stay inside the 95-character limit. Old format 1 uses `%012llx` and a different prefix (`src/librbd/ImageCtx.cc:242-244`); not supported.

#### 2.1.2 Where objects live (pool and namespace)

- Metadata objects (`rbd_id.*`, `rbd_directory`, `rbd_header.*`) are addressed in the metadata pool.
- Data objects are addressed in the **data pool**. If `get_data_pool` returns -1 the data pool is the metadata pool; otherwise it is the returned pool id (`src/librbd/image/OpenRequest.cc:478-494`).
- The data pool inherits the RADOS namespace of the metadata IO context unless one is given explicitly (`src/librbd/Utils.cc:145-169`). The namespace is part of the placement hash input: when it is not empty, the hashed key is `namespace`, byte 0x1F, `key` (`src/osd/osd_types.cc:1794-1805`). v1 uses the empty namespace only, see 4.

### 2.2 The `call` op that carries every class method

Every method in 2.3 and 2.7 is invoked with the OSD op `CEPH_OSD_OP_CALL` (numeric value 0x1401, see 2.11). The op's payload (the data segment of that op) is the concatenation of: class name bytes, method name bytes, input bytes, with no separators or terminators. The fixed per-op header is the 38-byte `ceph_osd_op` struct: `u16 op`, `u32 flags`, a 28-byte union, `u32 payload_len`; for a call the union starts with `class_len u8`, `method_len u8`, `argc u8`, `indata_len u32` and the rest is zero (`src/include/rados.h:585-605,667-669`, size check `:671-678`). librbd fills `class_len`, `method_len` and `indata_len`, appends the three strings to the op payload, and leaves `argc` at 0 because the whole op struct is zeroed first **[confirmed: all 978 CALL ops in the crc captures have argc 0, the rest of the union zero, `payload_len` = class_len + method_len + indata_len; rbd_check.py "call op record"]** (`src/osdc/Objecter.h:227-243`, zeroing in `src/osd/osd_types.h:4296-4299`). The OSD reads the three byte strings in that order using the two length bytes and `indata_len` and never looks at `argc` (`src/osd/PrimaryLogPG.cc:6209-6212`, `src/osd/osd_op_util.cc:172-178`). Class and method names are therefore limited to 255 bytes each.

Reply side (the exact MOSDOpReply framing belongs to the MOSDOp note): for every op of the request the reply carries the op struct back with `payload_len` set to that op's output length, a per-op `i32 rval`, and one data segment that is the **concatenation of all ops' outputs in op order** (`src/osd/osd_types.cc:7408-7416`, `src/messages/MOSDOpReply.h:171-211`). A client splits the data segment by the per-op `payload_len`. For a call the OSD also copies the output length into the op's extent length field (`src/osd/PrimaryLogPG.cc:6256`), which a client should not rely on **[confirmed: union bytes 8..15 of every CALL reply equal its `payload_len`]**. The overall request result is the first failing op's error (`src/osd/PrimaryLogPG.cc:9188-9195`; an op carrying the FAILOK op flag, `CEPH_OSD_OP_FLAG_FAILOK`, does not fail the request); the outputs of the ops before the failing one **are** delivered; the failing op carries its error as `rval` and has no output, the ops after it keep `rval` 0 and have no output; with `FAILOK` (per-op flag 0x2) on the failing op the request result is 0, that op keeps its negative `rval`, and the later ops still run and return their output **[confirmed: probe-a steps t18.fail_*, rbd_check.py "multi-op class calls"]**. A request that only reads fails as a whole with `-ENOENT` when the target object does not exist, before any op runs (`src/osd/PrimaryLogPG.cc:2526-2537`): result -2, every `rval` 0, no output **[confirmed: pcap/k2-rbd-info-v1 (`rbd_mirroring`), probe-a t18.missing_object_*, t19.read_missing]**. That is different from a method that itself returns `-ENOENT` on an object that exists (for example `dir_get_name` on `rbd_directory`): there the op's `rval` is -2 as well as the request result, and in a mutating request a `DELETE` of a missing object does the same **[confirmed: pcap/k2-rbd-create-rm, probe-a t19.delete_missing]**.

Errors: a class that cannot be opened maps to `-EOPNOTSUPP` when the loader says "not found", to the permission error when it says "not permitted", and to `-EIO` otherwise; a method that is not registered also gives `-EOPNOTSUPP` (an unknown method in `rbd` gave -95; an unknown class name, `t0nosuchclass`, gave `-EPERM` (1), not `-EOPNOTSUPP`; the code path that produces it was not read) **[confirmed: probe-a t4.unknown_method, t4.unknown_class]** (`src/osd/osd_op_util.cc:181-196`, repeated in `src/osd/PrimaryLogPG.cc:6228-6233`). These checks run in the request-classification step, so they fail the whole request before any op executes.

Permission: the OSD capability of the cephx identity must allow executing class methods **[confirmed: a client with `osd 'allow r pool=winrbd'` gets -EPERM for `get_id` while STAT works (pcap/x-t0-ro); `profile rbd-read-only` runs `get_size`, `get_features`, `lock get_info` and STAT, and is refused `lock lock`, `rbd set_id` and a WRITE with -EPERM (probe-a t16.*)]**. `class-read` is needed for methods registered as read-only, `class-write` for write methods, or plain `x` for both (`src/osd/OSDCap.cc:296-317`, `doc/rados/operations/user-management.rst:223-229`). `profile rbd` gives read, write and execute on the pool; `profile rbd-read-only` gives read and class-read (`src/osd/OSDCap.cc:332-369`, `doc/rados/operations/user-management.rst:286-306`; the `rbd` profile grants `r`, `w`, `x`, and `rbd-read-only` grants `r` plus class-read on the pool). Every method a v1 client uses is registered read-only (`src/cls/rbd/cls_rbd.cc:8393-8815`, including `get_id` and `dir_get_id` / `dir_get_name` at `:8557-8570`; `src/cls/lock/cls_lock.cc:625-645`), except lock `lock`, `unlock`, `break_lock`, `set_cookie`, which are registered as read-write (both flags), so a cap needs class-read **and** class-write for them (`src/cls/lock/cls_lock.cc:625-645`); `assert_locked` is read-only.

The classes `rbd` and `lock` are in the default OSD load list and in the default execute-permission list (`src/common/options/osd.yaml.in:671-683`). The `rbd` class declares itself version 2.0 and the `lock` class 1.0 (`src/cls/rbd/cls_rbd.cc:75`, `src/cls/lock/cls_lock.cc:35`); the call op carries no version, so a client never negotiates it.

### 2.3 `rbd` class methods a client uses (read side)

Object column: `H` = `rbd_header.<id>`, `I` = `rbd_id.<name>`, `D` = `rbd_directory`. "Input" and "Output" list the exact bytes in order.

| Method | Obj | Input | Output | Errors / notes | Server code |
|---|---|---|---|---|---|
| `get_id` | I | none | `string id` | `-ENOENT` if object missing or empty (size 0); `-EIO` if the stored data does not decode as a string | `src/cls/rbd/cls_rbd.cc:2784-2811` (client `cls_rbd_client.cc:1170-1182`) |
| `dir_get_id` | D | `string name` | `string id` | `-ENOENT` if no such name | `cls_rbd.cc:3050-3072` (client `cls_rbd_client.cc:1216-1232`) |
| `dir_get_name` | D | `string id` | `string name` | `-ENOENT` | `cls_rbd.cc:3084-3108` (client `cls_rbd_client.cc:1249-1263`) |
| `get_size` | H | `u64 snap_id` (use `CEPH_NOSNAP` for head) | `u8 order`, `u64 size` (**order first, then size**) | `-ENOENT` if header missing or snapshot unknown (the `order` key is read before the size) | `cls_rbd.cc:981-1022` (client `cls_rbd_client.cc:169-189`) |
| `get_features` | H | `u64 snap_id` (read and ignored; the server comment calls it deprecated), then **optional** `bool read_only` (absent = false) | `u64 features`, `u64 incompatible` | `-EINVAL` if the first u64 is missing (empty or 4-byte input) **[confirmed: probe-a t4.get_features.*]**; any value of the `read_only` byte and extra trailing bytes are accepted. `incompatible` is computed by the server from its own masks (2.8) | `cls_rbd.cc:869-898` (client `cls_rbd_client.cc:50-72`) |
| `get_object_prefix` | H | none | `string object_prefix` | `-ENOENT` / error if the key is missing | `cls_rbd.cc:2145-2160` (client `cls_rbd_client.cc:107-122`) |
| `get_snapcontext` | H | none | `u64 snap_seq`, `vector<u64> snap_ids` (descending), see 2.5 | error if `snap_seq` key is missing | `cls_rbd.cc:2098-2138` (client `cls_rbd_client.cc:637-655`) |
| `get_data_pool` | H | none | `i64 data_pool_id` (-1 = none) | returns -1 when the key is absent, so it is safe on any image; `-EOPNOTSUPP` only from an OSD that does not know the method, librbd treats that as -1 | `cls_rbd.cc:2170-2185`; tolerance at `OpenRequest.cc:463-469` |
| `get_stripe_unit_count` | H | none | `u64 stripe_unit`, `u64 stripe_count` | `-ENOEXEC` (8) if the STRIPINGV2 bit is not set **[confirmed: probe-a t4.get_stripe_unit_count.nostriping; with the bit set it returns `00 00 01 00 00 00 00 00` + `04 00 00 00 00 00 00 00` = 65536, 4]** (so call it only when the bit is set; librbd also tolerates `-ENOEXEC` / `-EINVAL` here and keeps the defaults). If the keys are absent the server answers `stripe_unit = 1 << order`, `stripe_count = 1` | `cls_rbd.cc:1216-1254`; client tolerance `OpenRequest.cc:343-345` |
| `get_flags` | H | `u64 snap_id` | `u64 flags` | absent key reads as 0 for head | `cls_rbd.cc:1433-1465` |
| `op_features_get` | H | none | `u64 op_features` | absent key reads as 0 | `cls_rbd.cc:1547-1560` |
| `parent_get` | H | none | `ParentImageSpec` (struct header v1, compat 1, then `i64 pool_id`, `string pool_namespace`, `string image_id`, `u64 snap_id`). Default (no parent) is `pool_id = -1`, empty strings, `snap_id = CEPH_NOSNAP` | does not fail when LAYERING is off or no parent key exists, it returns the default. When the head has no `parent` key it also looks at the oldest snapshot record for a legacy embedded parent and returns that (`cls_rbd.cc:1744-1762`), so a default-looking reply is only authoritative together with `parent_overlap_get` and the LAYERING bit | `cls_rbd.cc:1734-1769`; spec layout `cls_rbd_types.cc:508-524` |
| `parent_overlap_get` | H | `u64 snap_id` | `optional<u64> overlap` (`u8 present`, then `u64` if present) | not set = no parent overlap; returns not-set when LAYERING is off | `cls_rbd.cc:1779-1824` |
| `get_parent` (legacy) | H | `u64 snap_id` | `i64 pool_id`, `string image_id`, `u64 snap_id`, `u64 overlap` | `-EXDEV` if the parent is in a non-default namespace. Used by librbd only as a fallback when `parent_get` returns `-EOPNOTSUPP` | `cls_rbd.cc:1609-1670`; fallback `RefreshRequest.cc:523-527` |

A parent "exists" when `pool_id >= 0`, `image_id` is not empty and `snap_id != CEPH_NOSNAP` (`src/cls/rbd/cls_rbd_types.h:297-299`).

Methods that a minimal client skips: `get_create_timestamp`, `get_access_timestamp`, `get_modify_timestamp` (OpenRequest reads them, `OpenRequest.cc:358-439`, but they carry no data-path meaning), `metadata_list`, `image_group_get`, `snapshot_get` and the per-snapshot readers, `get_protection_status`, `get_children`, `migration_get`, `get_all_features`, all `object_map_*`.

### 2.4 Header object omap keys (informational, for cross-checking with `rados listomapvals`)

Values are encoded with the same primitives as above, one value per key. A client that wants to avoid the class call could read these keys directly with an omap read, but the class route is what librbd does and keeps the output encodings stable, so this table is a verification aid, not a recommended path.

| Key | Value encoding | Meaning | Source |
|---|---|---|---|
| `size` | u64 | image size in bytes at head | `cls_rbd.cc:816,824` |
| `order` | u8 | object size = `1 << order` | `cls_rbd.cc:817,825` |
| `features` | u64 | feature bits | `cls_rbd.cc:818,826` |
| `object_prefix` | string | data object prefix | `cls_rbd.cc:819,827` |
| `snap_seq` | u64 | highest snapshot id ever allocated for the image | `cls_rbd.cc:820,828` |
| `create_timestamp`, `access_timestamp`, `modify_timestamp` | `utime_t` (u32 sec, u32 nsec) | times | `cls_rbd.cc:821,829-831` |
| `data_pool_id` | i64 | only when DATA_POOL is set | `cls_rbd.cc:838-846` |
| `stripe_unit`, `stripe_count` | u64 each | only for non-default striping (written together by `set_stripe_unit_count`) | `cls_rbd.cc:1305,1312` |
| `flags` | u64 | image flags (key absent = 0) | `cls_rbd.cc:1447` (read), `:1526` (write) |
| `op_features` | u64 | operation feature bits | `cls_rbd.cc:325-327` |
| `parent` | `cls_rbd_parent` (struct header; v2 written by Nautilus-or-later OSDs) | clone parent | `src/cls/rbd/cls_rbd.h:45-66` |
| `snapshot_<16 hex digits of snap id>` | `cls_rbd_snap` | one per snapshot | `cls_rbd.cc:79,161-167` |
| `metadata_<key>` | string | user metadata | `cls_rbd.cc:83` |

Observed key sets **[confirmed: gt4 and probe-a t3.omap.*, rbd_check.py]**: a plain image has exactly `size`, `order`, `features`, `object_prefix`, `snap_seq` and the three timestamps; `stripe_unit` + `stripe_count` appear only for the striped image (u64 each), `data_pool_id` only for the data-pool image (i64), `parent` only for the clone, `snapshot_<16 hex>` per snapshot; `flags` and `op_features` are absent when 0. The `parent` value of a clone starts `02 02 <u32 len>` (struct v2, compat 2). The key and prefix constants are listed at `cls_rbd.cc:62-83`. The `parent` and `snapshot_*` values change encoding with the OSD release (`cls_rbd.cc:87-94`), which is why the class calls, not raw omap reads, should be used for them.

### 2.5 Snapshot context (SnapContext) encoding and rules

`get_snapcontext` output, and the snapshot context a writer must send, have this layout (no struct header; `src/common/snap_types.h:94-103`):

| Field | Type | Meaning |
|---|---|---|
| `seq` | u64 | the image's `snap_seq` (highest snapshot id ever used) |
| `snaps` | `vector<u64>` | ids of the snapshots that currently exist, **strictly descending**; every id is at most `seq` |

Validity (`src/common/snap_types.cc:99-117`): `seq <= CEPH_MAXSNAP`; if the list is not empty, the first element is at most `seq`, and every following element is strictly smaller than the previous one and the previous one is not 0. librbd rejects a context that fails these checks (`src/cls/rbd/cls_rbd_client.cc:651-653`, and `-EIO` at `RefreshRequest.cc:434-438`).

Example bytes: seq 5, snapshots 5 and 3 -> `05 00 00 00 00 00 00 00` `02 00 00 00` `05 00 00 00 00 00 00 00` `03 00 00 00 00 00 00 00`.

The snapshot list includes every snapshot id with a `snapshot_` key, including snapshots in the trash namespace (`cls_rbd.cc:2102-2122`). Observed with snapshots 9 and 11 left after removing 10: seq 11, ids [11, 9] (descending, the gap stays) **[confirmed: probe-a t14.matrix.t0-feat-snap]**.

### 2.6 Compound reads that librbd issues at open

These are the actual op vectors, useful to compare a capture against.

Step A, `OpenRequest` (`src/librbd/image/OpenRequest.cc:255-313`), all on `rbd_header.<id>`, one request, three `call` ops in this order:

1. `rbd get_size` with input `u64 CEPH_NOSNAP` (bytes `FE FF FF FF FF FF FF FF`)
2. `rbd get_object_prefix` with empty input
3. `rbd get_features` with input `u64 CEPH_NOSNAP` + `bool true` (9 bytes: `FE FF FF FF FF FF FF FF 01`); librbd passes `read_only = true` here (`OpenRequest.cc:266`)

Then, as separate requests, `get_stripe_unit_count` (only if STRIPINGV2 is set; `:306-310`), `get_create_timestamp`, `get_access_timestamp` + `get_modify_timestamp` (`:358-439`), and `get_data_pool` (`:441-497`).

Step B, `RefreshRequest::send_v2_get_mutable_metadata` (`src/librbd/image/RefreshRequest.cc:354-385`), on `rbd_header.<id>`, one request, five `call` ops in this order:

1. `rbd get_size` (input `CEPH_NOSNAP`)
2. `rbd get_features` (input `CEPH_NOSNAP` + `bool read_only`)
3. `rbd get_flags` (input `CEPH_NOSNAP`)
4. `rbd get_snapcontext` (empty input)
5. `lock get_info` with the lock name `rbd_lock` (2.7)

Decode order is the op order (`RefreshRequest.cc:393-419`). A failure of any op fails the request, so ops that can legitimately fail must not be mixed in (see 3.2).

Step C (same file, `:468-542` and `:605-649`): `parent_get` + `parent_overlap_get(CEPH_NOSNAP)` in one request; `op_features_get` only if OPERATIONS is set; `image_group_get`; then the snapshot readers.

### 2.7 `lock` class and the image lock record

Class name `lock`. Methods (`src/cls/lock/cls_lock.cc:625-645`): `lock`, `unlock`, `break_lock`, `get_info`, `list_locks`, `assert_locked`, `set_cookie`. The state of a named lock is stored in the **xattr** `lock.<lock name>` of the object the method runs on (`cls_lock.cc:38,54-55`). For an image the object is `rbd_header.<id>` and the lock name is `rbd_lock` (`src/include/rbd_types.h:62`), so the xattr is `lock.rbd_lock`.

Enumerations and flags (`src/cls/lock/cls_lock_types.h:13-21`):

| Name | Value |
|---|---|
| lock type NONE | 0 |
| lock type EXCLUSIVE | 1 |
| lock type SHARED | 2 |
| lock type EXCLUSIVE_EPHEMERAL | 3 (lock object removed at unlock; not used by RBD) |
| flag MAY_RENEW | 0x1 |
| flag MUST_RENEW | 0x2 |

`get_info` (client side `cls_lock_client.cc:134-168`; server `cls_lock.cc:382-412`):

| Direction | Layout |
|---|---|
| Input | struct header v1/compat 1, then `string name` (e.g. `rbd_lock`). Example for `rbd_lock`: `01 01 0C 00 00 00 08 00 00 00 72 62 64 5F 6C 6F 63 6B` |
| Output | struct header v1/compat 1, then `map<locker_id_t, locker_info_t> lockers`, `u8 lock_type`, `string tag` (`cls_lock_ops.h:125-153`) |

`locker_id_t` (`cls_lock_types.h:60-95`): struct header v1/compat 1, then `entity_name_t locker` (`u8 type`, `i64 num`, 9 bytes, no header; `src/msg/msg_types.h:49-51,95-98`, `typedef uint8_t entity_type_t` at `src/include/msgr.h:89`; type codes MON 0x01, MDS 0x02, OSD 0x04, CLIENT 0x08, MGR 0x10, `msgr.h:91-95`) and `string cookie`. The map is ordered by (type, num, cookie) (`cls_lock_types.h:80-86`), which a decoder need not rely on. For a client entity the type is the client type and `num` is the global id of that cephx session. `locker_info_t` (`cls_lock_types.h:97-138`): struct header v1/compat 1, then `utime_t expiration` (u32 sec + u32 nsec, raw little-endian, no header, `src/include/utime.h:163-171`; zero = never expires), `entity_addr_t addr` (msgr address, see msgr2 note), `string description`. The `addr` encoding depends on the feature bits of the **requesting** connection, because the OSD re-encodes the record for the reply with the caller's features (`cls_lock.cc:409`, `src/msg/msg_types.h:476-517`): with the MSG_ADDR2 feature it is `u8 marker = 1`, a struct header v1/compat 1, then `u32 type` (NONE 0, legacy v1 1, msgr2 2, any 3; `msg_types.h:240-243,258`), `u32 nonce`, `u32 sockaddr_len`, then that many bytes of sockaddr (`u16` family first) (`msg_types.h:476-517`); without it, a legacy form is produced instead: `u32 0` (so the first byte is a marker 0), `u32 nonce`, and a fixed 128-byte `sockaddr_storage` with no length (`msg_types.h:441-475`, byte order of the family field in that form not read **[unverified]**). The lock record on disk stores the address with type forced to legacy (`cls_lock.cc:228-233`) **[confirmed: probe-a, `lock get_info` with a live locker from a client that advertises MSG_ADDR2: `01 01 01 1c 00 00 00` (marker 1, struct v1/compat 1, len 28), `u32 type` = 1, `u32 nonce` (equal to the nonce of the client's own address in its CLIENT_IDENT), `u32 elen` = 16, family 2, port 0, address; the locker entity number equals the global id of the connection that sent `lock`]**. Since `locker_info_t` has its own struct length, a client does not need either form. A client that only needs "is there a locker, who holds it, what tag" can **skip `locker_info_t` by its struct length**, and skip `locker_id_t` after reading the cookie, so it does not need to decode `entity_addr_t`.

Inputs of the write-side lock methods (needed only by writer policy L2, 3.9). All are a struct header v1/compat 1 followed by the fields in this order (`src/cls/lock/cls_lock_ops.h:11-51` lock, `:53-75` unlock, `:77-102` break, `:176-207` assert, `:209-243` set_cookie; client builders `src/cls/lock/cls_lock_client.cc:29-45`):

| Method | Fields after the struct header |
|---|---|
| `lock` | `string name`, `u8 lock_type`, `string cookie`, `string tag`, `string description`, `utime_t duration` (u32 sec, u32 nsec; zero = no expiry), `u8 flags` |
| `unlock` | `string name`, `string cookie` (the locker entity is the caller) |
| `break_lock` | `string name`, `entity_name_t locker` (`u8 type`, `i64 num`), `string cookie` |
| `assert_locked` | `string name`, `u8 lock_type`, `string cookie`, `string tag` |
| `set_cookie` | `string name`, `u8 lock_type`, `string cookie`, `string tag`, `string new_cookie` |

Example `lock` input for name `rbd_lock`, EXCLUSIVE, cookie `c`, tag `t`, empty description, duration 0, flags 0 (42 bytes; **[confirmed: sent verbatim, accepted with result 0, probe-a t20.lock.note_example]**): `01 01 24 00 00 00` `08 00 00 00 72 62 64 5F 6C 6F 63 6B` `01` `01 00 00 00 63` `01 00 00 00 74` `00 00 00 00` `00 00 00 00 00 00 00 00` `00`. Validity checks of `lock`: the type must be 1, 2 or 3 (`cls_lock_types.h:47-51`), the name must not be empty, and MAY_RENEW and MUST_RENEW must not both be set, otherwise `-EINVAL` (`cls_lock.cc:145-162`). A call whose input does not decode is answered with `-EINVAL` (`cls_lock.cc:264,336,364,390`).

Semantics worth knowing:

- No lock present: `get_info` succeeds with an empty map, type 0, empty tag (`cls_lock.cc:58-62`, an existing object without the lock xattr) **[confirmed: every image that never had a lock]**. A missing header object fails the whole request with `-ENOENT` **[confirmed]**. **Correction after capture:** this is only true for an object that never carried a lock. When the last locker goes away (unlock, break, expiry) the record is **kept**, with an empty map and the lock type and tag of the last holder: a released librbd lock reads as type 1, tag `internal`, no lockers (the default image in gt4); a released shared lock as type 2 **[confirmed: gt4 img-default, probe-a t20.get_info.after_unlock / end / expired]**. A client must decide "locked" from the locker map only, never from type or tag.
- Expired lockers (non-zero expiration in the past) are dropped from the result on read (`cls_lock.cc:77-91`) **[confirmed: a lock with duration 2 s showed an absolute expiration, and an empty map 3 s later, probe-a t20.get_info.expiring / expired]**. librbd's exclusive lock always uses duration 0 (no expiry).
- The locker identity is **not supplied by the client**: the OSD takes the entity name from the authenticated connection that sent the request (`cls_lock.cc:176-179`), and stores the locker's address with type legacy (`:228-233`).
- A second `lock` is refused with `-EBUSY` if the tag differs from the existing tag while lockers exist (`:183-186`), if an exclusive lock is requested and any other locker exists (`:205-213`), or if the existing lock type differs (`:214-217`). `-EEXIST` if the same locker id re-locks without MAY_RENEW (`:191-194`) **[confirmed: probe-a t20.lock.*: same cookie again -17; with MAY_RENEW 0; other cookie, other tag, or shared-vs-exclusive -16; type 0, empty name, MAY_RENEW|MUST_RENEW, garbage input -22]**.
- `unlock` requires the same entity (the caller) and cookie, else `-ENOENT` (`:282-343`) **[confirmed: wrong cookie and a second unlock both -2; `break_lock` of an absent locker -2; `assert_locked` with the wrong cookie or tag -16; `set_cookie` renames the caller's lock]**. `break_lock` removes a named locker (entity + cookie) held by anyone (`:355-368`).
- `assert_locked` succeeds only if the caller holds it with the given type, cookie and tag, else `-EBUSY` (`:470-521`).
- The lock is **advisory at the OSD** **[confirmed: probe-a t15.data_*: another cephx identity wrote, read back and removed a data object of an image whose lock was held with a foreign tag]**: data object writes do not check it. The only `assert_locked` uses in librbd are on object-map operations and in a lock self-check (`src/librbd/ObjectMap.cc:214`, `src/librbd/object_map/*.cc`, `src/librbd/ManagedLock.cc:290`); none in the data path (`src/librbd/io/`). This is a grep result over `src/librbd`; an OSD accepts data writes from a non-lock-holder **[confirmed: see above]**.

### 2.8 Feature bits

`src/include/rbd/features.h:7-18` (values), `:39-103` (masks). "RO-incompat" = in `RBD_FEATURES_INCOMPATIBLE`: an image with such a bit must not even be read by a client that does not implement the bit. "RW-incompat" = in `RBD_FEATURES_RW_INCOMPATIBLE`: must not be written by a client that does not implement it (read-only is allowed).

| Bit | Value | Name | RO-incompat | RW-incompat | Mutable at run time | Meaning in one line | v1 reader | v1 writer |
|---|---|---|---|---|---|---|---|---|
| 0 | 0x1 | layering | yes | yes | no | clones; absent object may mean "read the parent" | accept, require no parent | accept, require no parent |
| 1 | 0x2 | striping (STRIPINGV2) | yes | yes | no | non-default stripe unit / count stored in header | accept only if layout is default (2.9) | same |
| 2 | 0x4 | exclusive-lock | no | yes | yes | cooperative writer lock | accept | accept only under a lock policy, see 3.9 |
| 3 | 0x8 | object-map | no | yes | yes | per-object existence bitmap (needs exclusive-lock) | accept, ignore | **refuse** |
| 4 | 0x10 | fast-diff | no | yes | yes | object-map extension (needs object-map) | accept, ignore | **refuse** |
| 5 | 0x20 | deep-flatten | no | yes | disable only | snapshots of clones keep parent refs; affects flatten only | accept | accept |
| 6 | 0x40 | journaling | no | yes | yes | write-ahead journal (needs exclusive-lock) | accept, with caveat in 4.2 | **refuse** |
| 7 | 0x80 | data-pool | yes | yes | no | data objects in another pool | accept | accept |
| 8 | 0x100 | operations | no | yes | internal | `op_features` key is valid | accept | refuse in v1 |
| 9 | 0x200 | migrating | no | yes | internal | live migration in progress | **refuse** | **refuse** |
| 10 | 0x400 | non-primary | no | yes | yes (internal) | mirroring secondary image | refuse in v1 | **refuse** |
| 11 | 0x800 | dirty-cache | yes | yes | yes (internal) | acknowledged writes may exist only in a client-side persistent cache | **refuse** | **refuse** |

Seen on a live cluster **[confirmed: gt4 and probe-a t14.matrix.*, rbd_check.py "feature matrix"]**: images with 0x01, 0x05, 0x21, 0x25, 0x45 (journaling), 0x3D, 0x03 (layering + striping), 0x81 (layering + data-pool), 0x201 (layering + migrating, target of `rbd migration prepare`); `get_all_features` returns 0xFFF; `incompatible` equalled `features & mask` for every image and both `read_only` values (RO mask hit on bits 0x1, 0x2, 0x80; migrating 0x200 is only in the RW mask). The bits 0x100, 0x400 and 0x800 never appeared. `RBD_FEATURES_DEFAULT` = layering | exclusive-lock | object-map | fast-diff | deep-flatten = `0x3D` (61) (`features.h:20-24`; `rbd_default_features` in `src/common/options/rbd.yaml.in:44-55`). `RBD_FEATURES_ALL` is the OR of bits 0-11 = `0xFFF` (`features.h:57-68`). `RBD_FEATURES_SINGLE_CLIENT` (exclusive-lock, object-map, fast-diff, journaling, dirty-cache) are the features that only make sense with one writer (`features.h:84-90`); `rbd create --image-shared` clears them (`src/tools/rbd/Utils.cc:524-528`, `doc/man/8/rbd.rst:158-162`).

How the server computes `incompatible` in `get_features`: `features & RBD_FEATURES_INCOMPATIBLE` when `read_only` is true, else `features & RBD_FEATURES_RW_INCOMPATIBLE` (`cls_rbd.cc:893-894`). librbd then fails the open with `-ENOSYS` if `incompatible & ~RBD_FEATURES_ALL` is non-zero (`RefreshRequest.cc:427-432`). Since the server only knows its own bits, **a third-party client must compute its own refusal set** from `features` and its own supported mask, not rely on the `incompatible` field. The `incompatible` field is still worth logging.

Dependency chain (documented): object-map requires exclusive-lock; fast-diff requires object-map; journaling requires exclusive-lock (`doc/man/8/rbd.rst:152-157`). To downgrade a default image, disable in the reverse order: fast-diff, object-map, then (if wanted) exclusive-lock; librbd itself refuses to disable exclusive-lock while object-map or journaling is still on (`src/librbd/operation/DisableFeaturesRequest.cc:186-199`).

Operation features (`op_features` value, only valid when feature bit 8 is set; `features.h:105-119`):

| Bit | Value | Name | Meaning |
|---|---|---|---|
| 0 | 0x1 | clone-parent | this image has clone children |
| 1 | 0x2 | clone-child | this image is a clone (has a parent) |
| 2 | 0x4 | group | image is a member of a consistency group |
| 3 | 0x8 | snap-trash | some snapshots are in the trash namespace |

### 2.9 Layout (striping) fields

Image layout is `(object_size, stripe_unit, stripe_count)`:

- `object_size = 1 << order`, `order` from `get_size`. librbd creates images with order 12..25 (`src/librbd/image/CreateRequest.cc:106-110`); default 22 = 4 MiB (`rbd.yaml.in:483-490`).
- If STRIPINGV2 is not set, or `stripe_unit == 0` or `stripe_count == 0`: `stripe_unit = object_size`, `stripe_count = 1` (`src/librbd/ImageCtx.cc:220-225`). This is "default striping".
- The STRIPINGV2 bit is set at creation only when `stripe_unit != object_size` or `stripe_count != 1` (`CreateRequest.cc:212-215`). A reader will therefore normally see the bit only for real striping. The header keys `stripe_unit` / `stripe_count` are written only in that case (`CreateRequest.cc:478-484`).
- Constraints enforced at creation: both set or both unset; `stripe_unit` divides the object size and is not larger; `stripe_unit >= 512` (`CreateRequest.cc:66-81`; server check `cls_rbd.cc:1297-1301`).
- Number of data objects for an image of `size` bytes: `period = stripe_count * object_size`; `num_periods = ceil(size / period)`; `rem = size mod period`; if `0 < rem < stripe_count * stripe_unit` subtract `stripe_count - ceil(rem / stripe_unit)`; result `num_periods * stripe_count - that` (`src/osdc/Striper.cc:349-363`).

### 2.10 Byte range to object extent mapping

Documentation: `doc/dev/file-striping.rst:45-95`, `doc/architecture.rst:1377-1450`. Algorithm in `src/osdc/Striper.cc:181-270`. In words, for an image byte offset `cur`:

```
su  = stripe_unit            (if stripe_count == 1, treat su as object_size)
sc  = stripe_count
spo = object_size / su                    # stripe units per object
block        = cur / su                   # global stripe-unit index
stripe       = block / sc                 # row across the object set
pos          = block mod sc               # which object in the set
objectset    = stripe / spo
objectno     = objectset * sc + pos
in_obj_off   = (stripe mod spo) * su + (cur mod su)
run          = min(remaining, su - (cur mod su))
```

Emit `(objectno, in_obj_off, run)`, advance `cur` by `run`, repeat. Consecutive runs that land on the same object and are adjacent inside it are merged into one extent (the librbd code keeps "one extent per object" and remembers the buffer ranges). The inverse mapping is in `Striper.cc:272-307` (not needed by a data-path client).

Default striping (`sc == 1`, `su == object_size`) reduces to `objectno = cur / object_size`, `in_obj_off = cur mod object_size`, run limited by the object boundary.

Worked examples:

| Layout | Image range | Result |
|---|---|---|
| default, 4 MiB objects | offset 10 MiB, length 8 MiB | object 2 offset 2 MiB length 2 MiB; object 3 offset 0 length 4 MiB; object 4 offset 0 length 2 MiB |
| su 64 KiB, sc 4, object 4 MiB (spo = 64, period 16 MiB) | offset 327680 (= 5 x 64 KiB), length 4096 | block 5, stripe 1, pos 1 -> object 1, in-object offset 65536, length 4096 |
| same | offset 16 MiB | block 256, stripe 64, pos 0, objectset 1 -> object 4, in-object offset 0 |

### 2.11 OSD ops used for the data path

Numeric values from the op table (`src/include/rados.h:227-245` for the mode/type bits, op list from `:247`): value = mode bits | type bits | number. Mode: read 0x1000, write 0x2000. Type: data 0x0200, attr 0x0300, exec 0x0400.

| Op | Value | Table line | Use |
|---|---|---|---|
| `CEPH_OSD_OP_READ` | 0x1201 | `rados.h:250` | normal read of `offset, length` |
| `CEPH_OSD_OP_SPARSE_READ` | 0x1205 | `:257` | read that also returns an extent map (librbd uses it when the request is at least `rbd_sparse_read_threshold_bytes`, default 64 KiB, `rbd.yaml.in:239-249`; a minimal client can use plain READ) |
| `CEPH_OSD_OP_STAT` | 0x1202 | `:251` | not needed |
| `CEPH_OSD_OP_WRITE` | 0x2201 | `:273` | write `offset, length` |
| `CEPH_OSD_OP_WRITEFULL` | 0x2202 | `:274` | replace the whole object (librbd uses it when a write covers exactly one whole object, `ObjectRequest.cc:371-374,665-668`) |
| `CEPH_OSD_OP_TRUNCATE` | 0x2203 | `:275` | discard of the tail of an object |
| `CEPH_OSD_OP_ZERO` | 0x2204 | `:276` | discard / write-zeroes of an inner range |
| `CEPH_OSD_OP_DELETE` | 0x2205 | `:277` | discard of a whole object |
| `CEPH_OSD_OP_CREATE` | 0x220D | `:289` | exclusive create, not used in the default write path |
| `CEPH_OSD_OP_SETALLOCHINT` | 0x2223 | `:321` | optional allocation hint (fields `expected_object_size u64`, `expected_write_size u64`, `flags u32`, `rados.h:652-656`) |
| `CEPH_OSD_OP_WRITESAME` | 0x2226 | `:328` | not needed |
| `CEPH_OSD_OP_CMPEXT` | 0x1220 | `:329` | not needed |
| `CEPH_OSD_OP_GETXATTR` | 0x1301 | `:341` | only if lock info is read from the xattr directly |
| `CEPH_OSD_OP_CALL` | 0x1401 | `:364` | class methods (2.2) |
| `CEPH_OSD_OP_WATCH` | 0x220F | `:292` | watch on the header object (not in v1) |

Op payload layouts (the `extent` struct is `offset u64`, `length u64`, `truncate_size u64`, `truncate_seq u32`, `src/include/rados.h:586-590`; the framing belongs to the MOSDOp note). How librbd fills it for the ops of this note (`src/osdc/Objecter.h:176-180,570-613`):

| Op | offset | length | payload | truncate_size / truncate_seq |
|---|---|---|---|---|
| READ, SPARSE_READ | in-object offset | bytes wanted | none | 0 / 0 |
| WRITE | in-object offset | payload length | the data | 0 / 0 |
| WRITEFULL | 0 | payload length | the whole new object | 0 / 0 |
| ZERO | in-object offset | bytes to zero | none | 0 / 0 |
| TRUNCATE | the new object size | 0 | none | 0 / 0 |
| DELETE | 0 | 0 | none | 0 / 0 |

A WRITE is rejected with `-EINVAL` when `length` differs from the payload length (`src/osd/PrimaryLogPG.cc:6743-6745`). Leaving the truncate fields at zero is what makes the OSD ignore them (`PrimaryLogPG.cc:5850-5853`, `:6768-6791`, `:6986-6997`). The OSD enforces `offset + length` below its maximum object size, default 128 MiB (`check_offset_and_length`, `PrimaryLogPG.cc:5368-5380`, option `src/common/options/global.yaml.in:3784-3787`); RBD objects are at most 32 MiB. Failure is `-EFBIG`.

OSD behaviour that a client can rely on (`src/osd/PrimaryLogPG.cc`):

- READ: `length == 0` means "to the end of the object"; a read starting at or beyond the object size succeeds with 0 bytes; a read that crosses the end is shortened to the end (`:5855-5864`). A missing object fails with `-ENOENT` (`:2526-2537`). **[confirmed: probe-a t10.read_*: READ(0, 0) of a 15-byte object returns all 15 bytes, READ(4, 0) the last 11, READ(16, 10) and READ(100, 10) return 0 bytes with result 0, READ(4, 100) returns 11 bytes]**
- SPARSE_READ reply: the op output is `map<u64,u64>` (`u32 count`, then offset / length pairs, relative to the object) followed by a bufferlist (`u32 length` + the data bytes of those extents back to back) (`src/osdc/Objecter.h:516-549`). Holes are simply absent from the map. **[confirmed for a fully written 64 KiB extent: pcap/k2-rbd-bench-v1 replies are `01 00 00 00`, offset, 0x10000, `00 00 01 00`, data (object-relative offsets)]**. A reply with a real hole was not captured, so the multi-extent case stays **[confirm on capture]**.
- WRITE on a missing object creates it (the write path calls `maybe_create_new_object`; no separate create op is needed).
- ZERO and TRUNCATE on a missing object are successful no-ops (`:6921-6931`, `:6975-6978`); DELETE on a missing object fails with `-ENOENT` (`:8308-8309`). TRUNCATE to an offset beyond the current size extends the object (`:7009-7013`). **[confirmed: probe-a t19.*: ZERO and TRUNCATE of a missing object return 0 and do not create it; DELETE returns -2 with rval -2; TRUNCATE to 3 MiB of a 1 MiB object gives size 3 MiB; a ZERO that reaches the end is echoed back as TRUNCATE and leaves the size at the offset; WRITE of 0 bytes on a missing object creates it with size 0, and at an offset past the end extends the object (Q5)]**
- SETALLOCHINT is advisory; librbd sets the per-op FAILOK flag on it so that an old OSD does not fail the request (`src/osdc/Objecter.h:1631-1641`) **[confirmed: all 420 captured SETALLOCHINT ops have per-op flags 0x2 and payload 4194304, 4194304, 0, always directly before the WRITE]**. Its payload is `expected_object_size u64`, `expected_write_size u64`, `flags u32` (`rados.h:652-656`); librbd sends the object size twice and `flags` from its config (0 by default) (`src/librbd/io/ObjectRequest.cc:135-146`).

For data objects the OSD uses the snapshot context from the request only if the pool is not in pool-snapshot mode; RBD pools use self-managed snapshots and take the client's context (`PrimaryLogPG.cc:4212-4221`). A pool in pool-snapshot mode would silently replace it with the pool's own context, so a client should refuse a pool whose OSDMap entry has the POOL_SNAPS flag (bit 14, `osdmap.md` 2.7.2; test at `src/osd/osd_types.cc:1717-1720`). librbd itself refuses to create an image in such a pool: `rbd create` fails with (22) "pool not configured for self-managed RBD snapshot support" **[confirmed: lab run, `rbd-extra/cli/q14.create-in-snappool.out`]**; an image that already lived in a pool that later changed mode was not tried.

### 2.12 Encoding versions: what v20.2.5 sends, what it accepts

| Item | What the server sends | What the server accepts from a client | Source |
|---|---|---|---|
| All `rbd` class methods in 2.3 except `parent_get` | bare primitives, no struct header, no version | inputs are bare primitives; a trailing field that is absent is tolerated only where stated (`get_features` `read_only`) | `cls_rbd.cc:869-898,981-1022,2098-2160` |
| `parent_get` output (`ParentImageSpec`) | struct v1, compat 1 | n/a (output only) | `cls_rbd_types.cc:508-524` |
| `parent` omap value (`cls_rbd_parent`) | n/a (not returned by any method in 2.3) | stored as v2 when the cluster's required OSD release is Nautilus or later, else v1 (observed: v2, compat 2 **[confirmed: probe-a t3.omap.t0-feat-clone]**) | `cls_rbd.h:46-52`, `cls_rbd.cc:87-94` |
| `lock get_info` output | `cls_lock_get_info_reply` struct v1/compat 1, containing `locker_id_t` v1/1 and `locker_info_t` v1/1 | `cls_lock_get_info_op` struct v1/compat 1; a decoder rejects `struct_compat` greater than 1 | `cls_lock_ops.h:104-153`, `cls_lock_types.h:60-138`, `include/encoding.h:1602-1621` |
| `lock lock/unlock/break_lock/assert_locked/set_cookie` input | n/a | struct v1/compat 1 each; send exactly `01 01 <len>` | `cls_lock_ops.h` |
| `entity_addr_t` inside `locker_info_t` | form depends on the requesting connection's feature bits (2.7) | n/a | `msg_types.h:476-517` |
| `SnapContext` | no header: `u64 seq`, `vector<u64>` | same, in the MOSDOp note | `snap_types.h:94-103` |

A minimal client never needs a version number other than 1 for anything in this note. The `rbd` class offers newer or alternative methods for snapshot, group, mirroring and migration data whose encodings carry their own versions; none is used here. Differences to Reef 18 / Squid 19 were not researched (6, Q12).

---

## 3. Client procedure

### 3.1 Resolve the image name to an id

1. Build the id object name `rbd_id.<name>` (`src/librbd/Utils.cc:51-54`).
2. Send `rbd get_id` (empty input) to that object in the metadata pool. Decode `string id` (`OpenRequest.cc:133-167`, server `cls_rbd.cc:2784-2811`). librbd first sends a separate `STAT` on `rbd_id.<name>` and only on success does the `get_id` call (`OpenRequest.cc:95-131`) **[confirmed: pcap/*-rbd-info-v1, two requests]**; the stat exists so that `-ENOENT` can be told apart and the format-1 probe started. A client may skip the stat and issue `get_id` directly: it answers `-ENOENT` for a missing object and also for an object of size 0, which happens while an image is being created or removed. The call is registered read-only (`cls_rbd.cc:8557-8559`).
   - Equivalent without a class call: a plain `READ` of the whole object (offset 0, length 0 meaning "to the end", `src/osd/PrimaryLogPG.cc:5855-5856`) returns the same `u32 len + id` bytes, because that is exactly what the method reads and decodes (`cls_rbd.cc:2786-2809`). librbd does not do this, so treat it as an alternative **[confirmed: probe-a t10.read_whole_len0, the reply is `0b 00 00 00` + the 11-byte id]**.
3. If the result is `-ENOENT`: librbd then probes for a format-1 header `<name>.rbd` (`OpenRequest.cc:115-131,56-92`). A v1 client may report "not found, or format 1 (unsupported)"; it may do the same stat on `<name>.rbd` only to give a better message.
4. Fallback (not what librbd does for open): `rbd dir_get_id` with input `string name` on `rbd_directory`. Useful for diagnostics only; the directory can be inconsistent with the id object only transiently (the design reason for having the id object at all is that opening must not depend on the single directory object, `doc/dev/rbd-layering.rst:173-180`).
5. Validate: the id is non-empty and alphanumeric (`cls_rbd.cc:235-244`); do not impose a 14-byte maximum (2.1.1).

If the user supplies an image id directly (the handoff table may carry the id), skip steps 1 to 4; librbd also supports opening by id, and then reads the name from the directory only for display (`OpenRequest.cc:169-207`).

### 3.2 Read the metadata

Send the following requests to `rbd_header.<id>` in the metadata pool. The split is chosen so that no request contains an op that can fail legitimately.

Request 1 (one request, six `call` ops), mirrors step B of 2.6 plus the object prefix:

1. `rbd get_size(CEPH_NOSNAP)` -> `order`, `size`
2. `rbd get_object_prefix` -> `prefix`
3. `rbd get_features(CEPH_NOSNAP, read_only)` -> `features`, `incompatible`
4. `rbd get_flags(CEPH_NOSNAP)` -> `flags`
5. `rbd get_snapcontext` -> `snap_seq`, `snap_ids`
6. `lock get_info("rbd_lock")` -> lockers, lock type, tag

All ops of one request are executed by the OSD against one object state in one pass, so size, snapshot context, features and lock record in request 1 are mutually consistent **[unverified]** (atomicity against a concurrent header update cannot be shown by a capture, and the OSD's object-lock behaviour was not read; Q16). Merging the OpenRequest and RefreshRequest vectors into one request is a simplification of this note; it is made of the same independent read-only calls, and the OSD returns all six outputs in one reply: result 0, six `rval` 0, six outputs in op order **[confirmed: probe-a t17.six_op.*]**. `read_only` should be true when the client will not write, false for a writer (this only changes the `incompatible` mask in the reply).

Request 2 (conditional ops chosen from `features`):

- `rbd get_data_pool` (always)
- `rbd parent_get` and `rbd parent_overlap_get(CEPH_NOSNAP)` (always, cheap; see 3.3 rule 6)
- `rbd get_stripe_unit_count` **only if** bit 0x2 is set
- `rbd op_features_get` **only if** bit 0x100 is set

The conditional calls follow the feature bits exactly: `get_stripe_unit_count` is issued iff 0x2 is set, `op_features_get` iff 0x100, and `get_stripe_unit_count` comes right after vector A and before `get_create_timestamp` / `get_data_pool` **[confirmed: all 58 librbd opens examined in the Phase 0 and probe captures (2 on the striped image); no image with bit 0x100 was available, so the `op_features_get` side is only confirmed as "absent when the bit is clear"]**. Keep `get_stripe_unit_count` in its own request if you want the same tolerance as librbd (it treats `-ENOEXEC` / `-EINVAL` as "keep defaults", `OpenRequest.cc:343-345`); in the profile of this note a failure there is simply a refusal.

### 3.3 Validate against the profile (refusal rules)

Apply in this order; the first failing rule refuses the open and returns a stable reason (4.6).

1. The header object exists (else not found).
2. `features & ~SUPPORTED_BITS_FOR_MODE` must be 0, with `SUPPORTED_BITS_FOR_MODE` from the table in 2.8 / 4.2. Report the offending bits.
3. Unknown bits at 0x1000 and above: refuse (`RBD_FEATURES_ALL` ends at bit 11).
4. `snap_ids` list valid per 2.5, else refuse.
5. Layout: `order` in 12..25 (an image outside that range was not created by librbd; refuse in v1); if bit 0x2 is set, `stripe_count == 1 && stripe_unit == 1 << order` else refuse in v1.
6. Parent: refuse if a parent exists (2.3 rule) or if bit 0x100 is set and `op_features & 0x2` (clone-child). **Correction after capture:** a clone made with `rbd clone` has `features` 0x1 and `op_features` 0: neither the `operations` bit nor clone-child is set, so only `parent_get` / `parent_overlap_get` (or the legacy `get_parent`) reveal a clone: `parent_get` returned (pool 2, namespace empty, parent image id, a real snapshot id) and `parent_overlap_get` the image size **[confirmed: probe-a t14.matrix.t0-feat-clone, t4.*clone; rbd info JSON]**. The second half of this rule never fired on this release; keep it as a belt-and-braces check only.
7. Data pool: if bit 0x80 is set, `data_pool_id >= 0`; the pool must exist in the OSDMap and be a replicated pool in v1 (pool type is in the OSDMap note); else refuse.
8. Flags: `flags` is only meaningful with object-map / fast-diff (`RBD_FLAG_OBJECT_MAP_INVALID` = 1, `RBD_FLAG_FAST_DIFF_INVALID` = 2, `src/include/rbd/librbd.h:67-68`; only these two exist in this tree). A reader ignores them. A writer refuses an image with any flag set. Properly disabling object-map / fast-diff clears the matching flag (`src/librbd/operation/DisableFeaturesRequest.cc:201-205,550-563`), so a P1 image made by `rbd feature disable` has `flags == 0`.
9. Size: `size` is the image size; the client exposes `floor(size / sector_size) * sector_size` and treats the tail as unavailable.

### 3.4 Build the I/O context

- `object_size = 1 << order`, `su`, `sc` from 2.9.
- `object_prefix` from the header.
- Data pool id (or metadata pool id when -1) and the RADOS namespace (empty in v1).
- Write snapshot context `(snap_seq, snap_ids)`, see 3.6.
- Reads of the head use snapshot id `CEPH_NOSNAP` in the request header.

Cache `size`, `snap_seq` and `snap_ids` in the client; see 3.8 for refresh.

### 3.5 Read path

For an image read `(offset, length)`:

1. `length == 0` completes immediately. `offset >= size` fails with `-EINVAL`; a request that crosses the end is clipped to the end (`src/librbd/internal.cc:1600-1623`).
2. Map the range to object extents (2.10).
3. For each extent send a `READ(in_obj_off, len)` (or `SPARSE_READ`) on `<prefix>.<objno as 16 hex digits>` in the data pool. The requests for different objects are independent and may be in flight at the same time.
4. Result handling for each extent (`src/librbd/io/ObjectRequest.cc:258-277`, `src/osdc/Striper.cc:461-521`):
   - `-ENOENT` (object does not exist): the whole extent reads as zeros. With no parent this is the final answer (`ObjectRequest.cc:259-296` falls to the parent path, which returns `-ENOENT` straight away when there is no parent overlap, `src/librbd/io/Utils.cc:109-117`; the caller then treats `-ENOENT` as success with no data and zero-fills, `src/librbd/io/ReadResult.cc:257-266`).
   - Success with fewer bytes than requested (the object is shorter than the end of the extent): copy what was returned and fill the rest of **that extent** with zeros.
   - Success with the full length: copy.
   - Any other error: fail the whole image request with that error (`ObjectRequest.cc:269-273`).
5. Assemble the extents back into the caller's buffer using the buffer ranges remembered in step 2 (for default striping each extent is contiguous in the buffer).
6. Never consult the object map for head reads. A read-only librbd client does not open the object map at all for the head (`RefreshRequest.cc:1037-1046`), it just reads the objects.

A read past the end of an existing object but inside the image is the "short object" case: the OSD shortens the read to the object size, returning fewer bytes, or 0 bytes with success when the offset is at or beyond the object size (`src/osd/PrimaryLogPG.cc:5855-5864`); a hole inside an object is returned by the object store as zeros **[confirmed: probe-a t10.read_hole_range / read_inside_hole: 4 KiB of `A`, zeros, 4 KiB of `B` at 1 MiB, one READ of 2 MiB returns 1 MiB + 4 KiB with zeros in the hole]**. Because the object size is only as large as the highest byte ever written (or truncated to), a short result is the normal case for a partly written object, not an error.

### 3.6 Write path

For an image write `(offset, data)` with the profile accepted for writing:

1. Fail with `-EINVAL` if `offset >= size` (same clip rule as reads). A block driver should reject out-of-range requests before this point.
2. Map to object extents (2.10).
3. For each extent send one request on the data object with the op `WRITE(in_obj_off, len, data)` (or `WRITEFULL` when `in_obj_off == 0 && len == object_size`, which librbd does, `ObjectRequest.cc:371-374,665-668`; for an existing object it is equivalent to a full-length write). The request header must carry the **snapshot context** (below). There is no separate "create object" step: a write to an object that does not exist creates it. librbd only issues an exclusive `CREATE` when the exclusive-create write flag is set (`ObjectRequest.cc:654-658`); outside the cache and scheduler layers, which only pass the flag through, the only place in `src/librbd` that sets it is the client-side encryption layer (`src/librbd/crypto/CryptoObjectDispatch.cc:388`), which a plain image does not use.
4. Optional: precede the write with `SETALLOCHINT(object_size, object_size, 0)` as librbd does when `rbd_enable_alloc_hint` (default true, `rbd.yaml.in:333-338`; `ObjectRequest.cc:135-146`). It is a hint only; omitting it is allowed **[confirmed: WRITE and WRITEFULL without it were accepted, probe-a t10.write_a/b and pcap/*-rados-small; the effect on BlueStore allocation was not measured, Q11]**.
5. Completion: the image write completes when all object writes completed. A single failure fails the request; the data already written to other objects stays written (same as librbd).

Snapshot context on writes:

- The OSD takes the snapshot context from the client request and decides copy-on-write from it: a clone of the head is made only when the context carries snapshot ids and the newest one is newer than the object's own last-seen snapshot sequence (`src/osd/PrimaryLogPG.cc:4212-4221` for taking the client's context, `:8691-8695` for the clone condition, which compares the newest snapshot id in the list, not `seq`, with the object's own snapshot sequence). **A writer that sends no or a stale context silently corrupts existing snapshots.** This is the rule behind the Phase 1 note in the roadmap.
- librbd builds the write context from the last `get_snapcontext` result, **only if the snapshot list is not empty**; otherwise it sends no context (`src/librbd/ImageCtx.cc:994-1012`, the emptiness check is at `:1002-1004`). Sending `(seq, empty list)` is semantically the same for clone decisions (the clone condition requires a non-empty list). Mirror librbd to keep captures comparable. **[confirmed: writes of `rbd bench` to an image without snapshots carry seq 0 and no ids; to an image with snapshots 9 and 11 they carry seq 11 and [11, 9], exactly the `get_snapcontext` result (probe-a, `rbd bench` on t0-feat-snap); the stale-context cases of T12 were not run]**
- The context in the request header is `seq` plus `snaps` in the same descending order (2.5).
- An optional safety flag `CEPH_OSD_FLAG_ORDERSNAP` (0x40, `src/include/rados.h:460`) makes the OSD fail a write with `-EOLDSNAPC` when the client's `seq` is older than the object's own sequence (`PrimaryLogPG.cc:4223-4227`). librbd does not set it for data objects (no use in `src/librbd`). It would only catch objects that already received a newer-context write, not the first write after a new snapshot, so it is a partial net, not a fix (see 3.8).

Write with a data pool that is an erasure-coded pool needs partial-overwrite support on the pool; out of v1 (4.2).

### 3.7 Discard, write-zeroes, flush

librbd mapping of an image-level discard to one object extent (`src/librbd/io/ObjectRequest.h:295-322`, ops at `ObjectRequest.cc:673-692`):

| Extent | Action | OSD op |
|---|---|---|
| whole object (`off == 0`, `len == object_size`) | remove object | `DELETE` |
| from `off` to the end of the object (`off + len == object_size`, `off > 0`) | truncate | `TRUNCATE(off)` |
| anything else | zero the range | `ZERO(off, len)` |

(A fourth action, create-then-truncate, exists only for images with a parent and a special discard flag, `ObjectRequest.h:298-306`, `ObjectRequest.cc:679-684`; not relevant to v1.) For all three, a result of `-ENOENT` is success when the image has no parent: the write result handler only branches on `-ENOENT` when copy-up is enabled and otherwise falls through to completion (`ObjectRequest.cc:522-558`, `:527-531`). The OSD itself answers `-ENOENT` only for DELETE; ZERO and TRUNCATE on a missing object are no-ops that succeed (2.11). An image-level discard is also pre-processed: when `rbd_skip_partial_discard` is true (default, `rbd.yaml.in:306-311`) each object extent is shrunk inward to a multiple of `min(rbd_discard_granularity_bytes, object_size)` (default 64 KiB, `rbd.yaml.in:313-317`; code `src/librbd/io/ImageRequest.cc:589-649`, option wiring `src/librbd/ImageCtx.cc:859-862`) and extents that vanish are dropped; when the granularity reaches the object size, an extent that ends exactly at the end of its object is left unchanged (the tail-truncation special case in that code). The shrinking is switched off when the image has the dirty-cache feature. A client is free to skip this and to treat discard as best-effort (v1 choice: advertise no discard, see 4.1).

Write-zeroes: a minimal client implements it either as `ZERO(off, len)` per extent (same result as a discard of the inner range, and the result reads back as zeros) or as an ordinary `WRITE` of zero bytes. Both are valid; `ZERO` frees space.

Flush: librbd's flush waits for all in-flight image requests, then runs the flush through the object dispatch layers (`src/librbd/io/ImageRequest.cc:655-698`); with no cache layers there is no OSD op for it **[unverified]** for the exact default layer chain. A v1 client implements flush as "wait until every previously accepted write has completed (reply received)", plus whatever the OSD reply semantics require (MOSDOp note).

### 3.8 Keeping the cached header state fresh

librbd registers a watch on the header object and is told about resizes, snapshot changes, feature changes and lock requests (`src/librbd/image/OpenRequest.cc:601-613`); it refreshes the metadata when told. When the image is opened with the user read-only flag, librbd does not register the watch at all (`:602-604`), so a read-only librbd client is in the same position as the v1 reader here. A v1 client that does not implement watch / notify has these exposures:

| Change made by another client while we are attached | Effect on a client with a stale view |
|---|---|
| a snapshot is created | writes keep using the old snapshot context, so the new snapshot's clone is not made by our writes; objects we write after the snapshot would also change what the snapshot shows (data corruption of the snapshot) |
| a snapshot is removed | harmless for correctness, only wasted clones |
| the image is shrunk (objects past the new end are trimmed) | writes past the new end would recreate trimmed objects; reads past the new end are no longer meaningful. After a later grow, the "new space reads as zeros" rule (`doc/dev/rbd-layering.rst:135-140`) would be broken by the resurrected data |
| the image is grown | harmless, the extra space is simply not used |
| features are changed | object-map or journaling could be enabled behind our back, after which our writes are unsafe (2.8) |

Minimum mitigation for v1 (needs no watch): re-issue the single compound read of 3.2 (request 1, only the five metadata calls plus lock info) on a timer and before any write if more than `T` seconds old, and adopt the new snapshot context, size and features atomically. `T` is a configuration value; its default is an open question (6, Q1). This narrows the exposure window; it does not close it. Closing it needs a header watch (6, Q1).

### 3.9 Exclusive-lock handling

What librbd does (reference behaviour):

- The exclusive lock object is only created when the image has the exclusive-lock feature, is opened read-write, and is not opened on a snapshot (`src/librbd/image/RefreshRequest.cc:890-896`).
- A read-write librbd client takes the lock **lazily on the first write**. Reads do not need the lock, unless the image uses the clone-copy-on-read option, the journaling feature or the persistent write-back cache (`src/librbd/ExclusiveLock.cc:162-169`, `src/librbd/exclusive_lock/ImageDispatch.cc:223-228`). With object-map off and journaling off, a normal reader never takes it.
- The lock is a `lock` class record on `rbd_header.<id>`: name `rbd_lock`, type EXCLUSIVE (or SHARED in shared mode), **cookie** = the text `auto ` followed by the decimal watch handle of the client's header watch, **tag** = the text `internal`, description empty, duration 0, flags 0 **[confirmed: pcap/*-rbd-bench-default, 20 lock calls: the handle equals the cookie field of the header's WATCH op (offset 0 of the op's union), `unlock` uses the same cookie]** (`src/librbd/managed_lock/Utils.cc:14-37`, `src/librbd/managed_lock/AcquireRequest.cc:107-123`). The lock name constant is `RBD_LOCK_NAME` (`src/include/rbd_types.h:62`).
- When another client already holds it: librbd reads the lock (`GetLockerRequest`). If the tag is not `internal`, or the cookie does not parse as `auto <number>`, or the locker's address is blank, the lock is treated as "locked by an external mechanism" and the attempt fails with `-EBUSY` **without breaking it** (`src/librbd/managed_lock/GetLockerRequest.cc:81-110`). The client then asks the owner to release by notifying the header watchers and waits (`src/librbd/ExclusiveLock.cc:260-277`).
- If the tag and cookie are librbd-style, librbd lists the watchers of the header object. If a watcher exists whose address matches the locker's address and whose cookie equals the handle in the lock cookie, the owner is alive and librbd does not break the lock. If there is no such watcher the owner is considered dead: librbd blocklists the owner at the monitor (`rbd_blocklist_on_break_lock`, default true, `rbd.yaml.in:283-289`), waits for the map update, then breaks the lock and takes it (`src/librbd/managed_lock/BreakRequest.cc:48-140`, `src/librbd/managed_lock/AcquireRequest.cc:132-173`; `doc/rbd/rbd-exclusive-locks.rst:68-98`). A blocklisted client is refused by every OSD afterwards (`-EBLOCKLISTED`, 108).
- The exclusive lock is cooperative: a client that does not take it can still write the data objects (2.7, **[confirmed: probe-a t15.data_*]**). The documentation says so in as many words: two uncoordinated clients simply interleave their writes (`doc/rbd/rbd-exclusive-locks.rst:50-55`).
- The documentation says the lock is incompatible with the manual advisory lock commands (`doc/rbd/rbd-exclusive-locks.rst:63-65`) and that the manual advisory lock (`rbd lock add`) does not restrict any I/O, it only prevents taking the same advisory lock again (`doc/man/8/rbd.rst:440-447`). Those commands use the same lock name `rbd_lock` (`src/librbd/internal.cc:1425`).
- krbd: the manual states that krbd acquires the lock for writes and discards, takes it for reads too only with `lock_on_read`, and has an `exclusive` option that turns off automatic lock transitions (`doc/man/8/rbd.rst:811-830`). Its exact protocol is **[unverified]** (kernel source not in tree; `rbd map` with a foreign lock held was not tried because a wedged kernel client could hang the lab VM).

What a v1 client does, by policy (4.5 chooses the default):

- **Policy L0 (read-only client).** Never take the lock. Reading needs none for the v1 profile (3.5 and the second bullet above). The client does not affect writers. It may observe `lock get_info` and show it.
- **Policy L1 (writer, no lock feature).** Accept only images where bit 0x4 is clear. No lock protocol exists for such images; whether to place an advisory marker (`lock` on `rbd_lock` with a project-specific tag and cookie, as `rbd lock add` does) is a convenience, not a safety mechanism. It makes `rbd lock ls` show who is using the image and stops a second user of the same advisory-lock convention.
- **Policy L2 (writer on an image that has exclusive-lock, "foreign tag lock").** Before the first write, `lock lock` on `rbd_header.<id>` with name `rbd_lock`, type EXCLUSIVE, a cookie and tag that **do not** follow the `auto <n>` / `internal` convention (for example tag `winrbd`, cookie `winrbd <random>`), flags 0, duration 0. Expected effect from the source above: librbd peers see an external lock, fail to acquire, never break it, never blocklist us; they wait and keep asking. If our client dies the lock stays until an administrator removes it (`rbd lock rm`). The OSD does not stop uncoordinated data writes, so this only protects against well-behaved librbd / krbd users. **Observed after capture** (Ceph 20.2.5 librbd, foreign lock held, no watcher on the header): `lock lock` with a foreign cookie and tag is accepted and `rbd lock ls` lists the holder; `rbd snap create` and `rbd resize` fail at once with (30) Read-only file system, they do not wait; `rbd bench` (a writer) never completes and spins on `lock get_info` + a pair of notify-family ops (0x1206 / 0x1207, not in 2.11) against the header object, several hundred iterations per second (184 polls in the first 0.4 s) and 7000 to 9000 packets per second for one stalled client (2.6 million packets in 338 s; it had to be killed); no peer broke the lock or blocklisted the holder or the killed client (no blocklist entry for the client address); after `break_lock` of the foreign record the same `rbd bench` completed **[confirmed: rbd-extra/cli/t15.*, probe-a tail (first 0.2 s of the loop), blocklist-after.txt, rbd_check.py "foreign-tag lock"]**. `rbd map` and the behaviour with a live watcher were not tried **[unverified]**. So L2 does keep stock librbd writers off the image, but a waiting librbd writer becomes a request storm against the OSD that holds the header, and snapshot and resize requests from other tools fail with EROFS.
- **Policy L3 (full participation, out of v1).** Take the lock with the `auto <handle>` cookie and `internal` tag, hold a header watch with that handle, answer the lock-request, snapshot and resize notifications (the notification payload formats are in `src/librbd/WatchNotifyTypes.h/.cc`, not read for this note), or be blocklisted by the next librbd writer. Requires watch / notify in the core.

Identity across the iPXE-to-Windows handoff: the locker entity is the cephx session of the connection that took the lock (2.7). The Windows driver opens a new session with a different global id, so it cannot `unlock` what iPXE locked; it can only `break_lock` the previous record (entity and cookie are visible in `get_info`) and take a new one, leaving a short unprotected window. See 6, Q2.

### 3.10 Close

There is nothing to tear down on the cluster for L0 and L1. For L2 release the lock with `lock unlock(name = rbd_lock, cookie)`; on failure or no network leave it and report. Pending writes must have completed first (3.7 flush).

---

## 4. Minimal-client choices

### 4.1 Summary table

| Area | v1 decision | Reason | Source |
|---|---|---|---|
| Format | format 2 only; reject format 1 | the roadmap scope; format 1 has a different header, prefix and name format | `OpenRequest.cc:56-131`, `ImageCtx.cc:242-244` |
| Name to id | `rbd get_id` on `rbd_id.<name>` | same as librbd, no directory dependency | 3.1 |
| Metadata access | `rbd` and `lock` class calls only; no raw omap parsing | stable output encodings | 2.3, 2.4 |
| Watch / notify | not in v1; periodic re-read instead | keeps the core small | 3.8 |
| Snapshots | the image may have snapshots; the client reads and sends the snapshot context; it neither creates nor reads snapshots | writers must preserve snapshots | 3.6 |
| Reading a snapshot (`snap_id` read) | optional later; needs `get_size(snap_id)` and the snapshot id in the read request header | not needed for boot | 2.3 |
| Striping | default only (`sc == 1`, `su == object_size`); the general formula is described for later | roadmap scope | 2.9, 2.10 |
| Data pool | supported when replicated | only changes the pool id used for data objects | `OpenRequest.cc:478-494` |
| Clones | refused | a missing object may mean "read from parent" | `doc/dev/rbd-layering.rst:65-72` |
| Namespaces | default namespace only | the namespace is part of placement hashing and of every locator | 2.1.2 |
| Sparse read | plain READ; `-ENOENT` and short results become zeros | simplest, matches librbd's result | 3.5 |
| Write | WRITE with snapshot context; no create step | 3.6 | |
| Discard | not advertised in v1 (best effort later); write-zeroes via ZERO or zero WRITE | discard is only a hint, so skipping it is always correct | 3.7 |
| Flush | wait for in-flight completions | no cache layer | 3.7 |
| Object map, fast-diff, journaling | writer refuses; reader ignores object map | writer would leave the map stale | 2.8, 4.2 |
| Exclusive lock | policy L0 for readers; writers per 4.5 | 3.9 | |
| Encryption format | cannot be detected from the feature bits; an image that was formatted for client-side encryption is, to every API that has not loaded the encryption, a raw image whose first bytes are an encryption header, so the guest would see unreadable data | the format is applied and loaded by the client layer when the user asks for it | `doc/rbd/rbd-encryption.rst:5-45`, `src/librbd/ImageCtx.cc:942-945` |

### 4.2 Proposed v1 image profile (exact values)

Terms: "features" is the `u64` from `get_features`.

**Profile P1: the recommended v1 read-write profile.**

- format 2, `features` is a subset of `{layering 0x1, deep-flatten 0x20, data-pool 0x80}`, that is `features & ~0xA1 == 0`. The usual values are `0x01` (layering only) and `0x21` (layering and deep-flatten).
- STRIPINGV2 bit clear (or set with `stripe_count == 1` and `stripe_unit == 1 << order`).
- exclusive-lock, object-map, fast-diff, journaling, operations, migrating, non-primary, dirty-cache all clear.
- no parent.
- `flags == 0`.
- `order` in 12..25 (default 22).
- metadata and data in a replicated pool; default namespace.
- snapshots allowed; the writer sends the snapshot context; see 3.8 for the staleness limit.

How to make such an image from a default one: `rbd feature disable <pool>/<image> fast-diff`, then `object-map`, then `exclusive-lock` (order from the dependency chain, 2.8). A default image has `0x3D`; after the three disables it has `0x21` (disabling object-map also switches fast-diff off in librbd, `src/librbd/operation/DisableFeaturesRequest.cc:180-183`). Creating directly: `rbd create --image-format 2 --image-feature layering --size <size> <pool>/<image>` gives `0x01`. `rbd create --image-shared` gives the same effect as clearing the single-client features, so the default `0x3D` becomes `0x21` (`src/tools/rbd/Utils.cc:524-528`).

**Profile P1-L: read-write with the exclusive-lock bit present** (`features & ~0xA5 == 0`, that is P1 plus `0x4`): the usual values are `0x05` and `0x25`. Allowed only with writer policy L2 (3.9) and only after the L2 behaviour is confirmed on a capture; until then it is refused for writing and accepted for reading.

**Profile R1: the read-only profile.** All of the following are accepted:

- `features & ~0x1FF == 0`, which allows the bits 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 and 0x100; bit 0x2 only in its default layout form (2.9). The usual default image `0x3D` is accepted for reading,
- migrating (0x200), non-primary (0x400), dirty-cache (0x800), unknown bits: refused,
- no parent; data pool replicated; default namespace.

Rationale for ignoring object-map and fast-diff on a reader: librbd's own read-only open does not load the head object map (`RefreshRequest.cc:1037-1046`). Journaling with a reader: a writer that crashed may leave journaled-but-not-applied updates that only the next lock owner replays; the reader sees a crash-consistent older state. That is acceptable for a read-only boot test and should be documented **[unverified]** against the journal replay code (not read).

### 4.3 What must be handled, what may be skipped

Must handle:

- name -> id, header reads (2.6, 3.2), feature check and refusal (3.3),
- default striping math and the 16-hex-digit object names,
- zero fill for `-ENOENT` and for short results,
- the write snapshot context (3.6),
- clip / range checks against `size`,
- the data pool indirection.

May skip, with an explicit refusal of images that need it: layering (parent reads and copy-up), object map, fast-diff, journaling, striping other than default, watch / notify, migration, mirroring, trash, groups, snapshot read, encryption, erasure-coded data pool, non-default namespace, op_features other than all-zero for writing.

### 4.4 I/O sizes

Size limit on the OSD: `osd_max_write_size` defaults to 90 and is shifted left by 20, so it is 90 MiB (`src/common/options/osd.yaml.in:808-816`); it is compared with the **total data length of the whole request**, not per op (`src/osd/PrimaryLogPG.cc:2186-2190`). That is larger than the maximum object size (32 MiB, order 25), so splitting at object boundaries is always enough for a one-object request; a request that batches several object writes must keep the sum below the limit. A client may split further; extents are independent.

### 4.5 Default policies

- Reader: L0.
- Writer on P1 (no exclusive-lock bit): L1 with the advisory marker **off** by default (it is only informative, and with the exclusive-lock bit absent nobody coordinates anyway). Concurrent mapping of the same image by two writers is an operator error that the cluster does not prevent (2.7).
- Writer on P1-L: refuse until L2 is confirmed; then L2. (L2 is now observed, see 3.9: it works as a fence against stock writers but causes the request storm described there; whether to accept that is still a project decision.)

### 4.6 Refusal reasons (stable identifiers for the core's error reporting)

| Id | When |
|---|---|
| `RBD_E_NOT_FOUND` | `rbd_id.<name>` missing (possibly format 1) |
| `RBD_E_BAD_ID` | id empty, not alphanumeric, or the object names built from it exceed 95 characters |
| `RBD_E_FEATURES` | unsupported bits (carry the bit mask) |
| `RBD_E_STRIPING` | non-default layout |
| `RBD_E_PARENT` | image is a clone |
| `RBD_E_DATA_POOL` | data pool missing from the OSDMap or not replicated |
| `RBD_E_SNAPC` | invalid snapshot context |
| `RBD_E_FLAGS` | writer and a flag is set |
| `RBD_E_LOCKED` | writer policy refused because a foreign lock is held |
| `RBD_E_PROTO` | a reply does not decode |

---

## 5. Test vectors needed

All of these use the stock command-line tools as the oracle, never the client under test, and run against a scratch pool that is not used for anything else. Scrub keys and cephx secrets from any capture.

| Id | What to capture | How to check |
|---|---|---|
| T1 | `rados -p <pool> get rbd_id.<name> -` for several names | bytes must be `u32 len + id`; an id such as `abc123` gives `06 00 00 00 61 62 63 31 32 33`; compare with `rbd info` `id:` |
| T2 | `rados -p <pool> listomapvals rbd_directory` | keys `id_<id>` and `name_<name>`; values are encoded strings (2.1) |
| T3 | `rados -p <pool> listomapvals rbd_header.<id>` for images with features `0x01`, `0x21`, `0x05`, `0x3D`, `0x02`-striped, data-pool | key set and value bytes match 2.4 |
| T4 | `rados -p <pool> exec rbd_header.<id> rbd get_size <8-byte input file>` and the same for `get_features`, `get_object_prefix`, `get_flags`, `get_snapcontext`, `get_data_pool`, `get_stripe_unit_count`, `parent_get`, `parent_overlap_get`, `op_features_get` | exact output bytes against 2.3; check the order-then-size layout of `get_size`; check `read_only` byte present and absent for `get_features` |
| T5 | a full network capture of `rbd info` and of `rbd bench --io-type read` (debug messenger logging or a packet capture of the msgr2 stream with the secrets scrubbed) | the op vectors of 2.6 (op order, input bytes) and the number of requests librbd issues at open |
| T6 | lock records: `rbd lock add <img> <id>`, `rbd lock ls`, `rados getxattr rbd_header.<id> lock.rbd_lock`, `rados exec rbd_header.<id> lock get_info <18-byte input>` | decode against 2.7; record locker entity, cookie, tag, address encoding as seen by a modern client |
| T7 | an image with the exclusive-lock feature, a librbd writer running (`rbd bench --io-type write`), then `lock get_info` and the watcher list (`rados listwatchers rbd_header.<id>`) | confirm cookie `auto <handle>`, tag `internal`, and that the handle equals the watcher cookie |
| T8 | default layout: write a known pattern through a trusted mapping, read every object with `rados get` | file offset to object mapping (2.10), hex object names, object sizes |
| T9 | striped layout (`--stripe-unit 65536 --stripe-count 4`, object size 4 MiB): write a pattern, read objects with `rados get` | the worked examples in 2.10 and the object count formula in 2.9 |
| T10 | sparse cases: (a) read a range with no objects; (b) write 4096 bytes at object offset 0 only and read 8192; (c) write at object offset 1 MiB only and read from 0 | zero fill rules (3.5); OSD result for READ past the end of an object |
| T11 | discard behaviour of the stock tools: full-object discard, tail discard, inner discard, with and without `rbd_skip_partial_discard` | object present / absent / size, matches the table in 3.7 |
| T12 | snapshot context: create a snapshot, write through our writer with the fresh context, then read the snapshot with stock tools and compare; repeat with a stale context | `rados listsnaps <object>`; confirms 3.6 and the exposure in 3.8; also verify that sending `(seq, empty)` after all snapshots were removed is accepted |
| T13 | data pool image (`rbd create --data-pool`) | prefix includes the metadata pool id (2.1.1); data objects appear in the data pool, not the metadata pool |
| T14 | feature matrix: images with `0x01`, `0x05`, `0x21`, `0x25`, `0x3D`, `0x45` (layering, exclusive-lock and journaling), `0x200` (during a migration prepare), a clone | accept / refuse decision per 4.2; a clone must be refused by rule 6 |
| T15 | foreign-tag lock (L2): add a lock on an exclusive-lock image with a non-`internal` tag; then try from a second host: `rbd bench --io-type write`, `rbd snap create`, `rbd resize`, `rbd map` (and its `--exclusive` form), and record exactly what each does (wait, `-EBUSY`, break, blocklist) | decides whether L2 is safe, see 3.9 |
| T16 | capabilities: run T4 with `profile rbd-read-only` and with a cap that has only `r` on the pool | which calls succeed; expected: class-read calls succeed with `profile rbd-read-only` |
| T17 | single request of six `call` ops (3.2 request 1) with a hand-built client versus librbd's two requests | same decoded values |
| T18 | reply framing of a multi-op request: capture the reply of librbd's step B (five ops) and of a request whose third op fails (for example `get_stripe_unit_count` on an image without the striping bit, placed between two good ops) | per-op `payload_len` and `rval`, one concatenated data segment, and whether the outputs of ops before the failing one are present (2.2, Q4) |
| T19 | OSD op semantics on a missing object: `ZERO`, `TRUNCATE`, `DELETE`, `WRITE` of length 0, `READ` of offset 0 length 0 | results match the table in 2.11 (ZERO and TRUNCATE succeed, DELETE gives `-ENOENT`, READ gives `-ENOENT`) |
| T20 | `lock lock` hand-built from the example bytes in 2.7 against a scratch image, then `rbd lock ls` and `lock get_info` | the locker, cookie and tag read back as sent; address encoding as seen with and without the MSG_ADDR2 feature advertised in the msgr2 handshake |

---

## 6. Open questions

Q1. **Header changes while attached (biggest correctness risk for a writer).** Without a header watch the client does not learn about new snapshots, resizes or feature changes (3.8). A writer with a stale snapshot context breaks snapshots silently. The mitigation in this note is polling the header on a timer; the interval, the cost on a boot disk, and whether polling is acceptable at all, are undecided. The alternative is implementing watch / notify (op `WATCH`, `NOTIFY_ACK`) at least to receive header-update notifications; the notification payloads were not read for this note. `CEPH_OSD_FLAG_ORDERSNAP` is a partial extra net only.

Q2. **Exclusive-lock policy L2 was inferred from reading librbd; the stock tools' reaction is now observed (3.9: EROFS for snapshot / resize, a spinning writer, no break, no blocklist), `rbd map` and a live lock owner are not.** What the stock tools do when the lock is held with a foreign tag (including the kernel driver, which is not in the tree) must be captured (T15). The lock identity does not survive the handoff from the iPXE client to the Windows driver (different cephx session); the driver must `break_lock` and re-lock, with a window in between. Whether to skip the lock until the Windows driver owns the disk is a design decision for the handoff note.

Q3. krbd behaviour with the exclusive-lock feature, object-map and fast-diff (the kernel source is not in this tree), including which feature bits it refuses at map time **[unverified]**; the manual's option list (`doc/man/8/rbd.rst:811-830`) is the only evidence.

Q4. (Answered after capture, see Corrections 8: six-op request works, outputs before a failing op are delivered.) The reply layout of a multi-op request is pinned in source (per-op `payload_len` and `rval`, one concatenated data segment, 2.2), and librbd already issues five-op vectors, but a six-op vector exactly as in 3.2 is not what librbd sends (T17), and whether the outputs of the ops before a failing op are delivered was not read (T18).

Q5. (Mostly answered after capture, see Corrections 7; erasure pools and `truncate_seq` stay open.) OSD semantics now pinned in `PrimaryLogPG.cc` (2.11): READ past or across the object end, READ of a missing object (`-ENOENT`), ZERO and TRUNCATE on a missing object (no-op success), DELETE on a missing object (`-ENOENT`). Still not read: how the object store returns a hole inside an object (expected zeros), WRITE with a length of 0, behaviour on erasure-coded pools, and the OSD behaviour when `truncate_seq` is non-zero (a client leaving it at 0 never reaches that code). T10 and T19 cover them.

Q6. Whether the object-map and the `flags` field need to be read by a reader at all when an image carries `RBD_FLAG_OBJECT_MAP_INVALID`: not for head reads in librbd, but not verified for a reader that would later read snapshots.

Q7. Erasure-coded data pools: the data pool feature allows them; they need pool-level overwrite support and a pool-type check from the OSDMap; out of v1, refused in 3.3 rule 7. The exact failure code from the OSD when overwrites are disabled was not read.

Q8. Namespaces: the metadata and data objects of an image in a non-default namespace use that namespace for every locator (and the namespace changes the placement hash, 2.1.2); the pool-level metadata object `rbd_info` is read through a context forced to the default namespace (`src/librbd/image/RefreshRequest.cc:46-47`, `:581-583`). v1 refuses, no further reading done.

Q9. Trash and rename: an image in the trash has no entry in the directory; `OpenRequest.cc:209-253` shows librbd finding its name in `rbd_trash`. Whether `rbd_id.<name>` still exists for a trashed image was not checked.

Q10. Image size not a multiple of the guest sector size, and images whose size changes under us: the client rounds down (3.3 rule 9); how the Windows driver reports a capacity change is a driver question.

Q11. Alloc hint: omitting `SETALLOCHINT` should be harmless but affects BlueStore allocation behaviour; not measured.

Q12. Reef 18 and Squid 19 differences: not researched. In the code paths read here there are only fallbacks for older releases (legacy `get_parent` at `RefreshRequest.cc:523-527`, legacy snapshot readers at `:710-716`, both labelled for removal); the v20.2.5 OSD still has both families of methods (`cls_rbd.cc:8443-8457`). One difference a client can see is `lock get_info`'s address encoding, which depends on the features the client advertises (2.7), not on the cluster release.

Q13. Maximum number of ops per request and whether any op-count or payload cap on the OSD side affects the six-op request; not read.

Q14. Pool snapshot mode: a pool in pool-snapshot mode makes the OSD ignore the client's snapshot context (`PrimaryLogPG.cc:4212-4216`). A client detects the mode from the pool record in the OSDMap: pool flag bit 14 (POOL_SNAPS) set means pool-snapshot mode (`src/osd/osd_types.cc:1717-1720`; flag table in `osdmap.md` 2.7.2). v1 rule (added in the cross-note pass): a writer refuses a data pool, and the metadata pool, that has bit 14 set (refusal id `RBD_E_SNAPC`). RBD itself refuses to create an image in such a pool (2.11) **[confirmed]**; the writer rule above stays as a defence for images that already exist.

Q15. Features the client must advertise to get decodable replies: `lock get_info` re-encodes the locker address according to the requester's feature bits (2.7). Which bits a minimal msgr2 client advertises, and so which `entity_addr_t` form it receives, is a msgr2 / handshake question; the proposal here is to skip the whole `locker_info_t` by its length so that either form is harmless.

Q16. Atomicity of the multi-op header read (3.2): whether another client's header update can land between the ops of one request was not read; the OSD executes the ops of a request in one pass but the object lock behaviour is not pinned here.

Q17. `osd_max_write_size` is compared with the whole request's data length (`PrimaryLogPG.cc:2186-2190`); the error number the client sees (`OSD_WRITETOOBIG`) and whether the limit is really counted in MiB on every path were not checked beyond that line.

### Corrections after capture

What the live cluster showed that differs from, or adds to, what this note said before. Evidence names as in the status line; every item is checked by `harness/tools/rbd_check.py`.

1. **`lock get_info` after the last locker leaves (2.7).** The note said "no lock present: empty map, type 0, empty tag". That holds only for an object that never carried the lock. A released lock keeps its type and tag (type 1, tag `internal` on a default image whose writer exited; type 2 after shared lockers were broken) with an empty locker map. Decide "locked" from the map only.
2. **Clone detection (3.3 rule 6).** A clone has features 0x1 and op_features 0; the `operations` bit and the clone-child op feature are not set. Only `parent_get`, `parent_overlap_get` or legacy `get_parent` reveal it.
3. **Unknown class name (2.2).** An unknown class name returns `-EPERM` (1), not `-EOPNOTSUPP`; an unknown method of a known class returns `-EOPNOTSUPP` (95).
4. **Two kinds of ENOENT (2.2).** A read-only request on a missing object fails as a whole (rval 0); a method returning `-ENOENT` on an existing object, or a `DELETE` of a missing object in a mutating request, sets the op's own `rval` to -2.
5. **Policy L2 (3.9, 4.5).** `rbd snap create` and `rbd resize` fail at once with EROFS; a stock writer spins at several hundred polls per second instead of waiting; nothing breaks the lock or blocklists the holder.
6. **Q14 resolved:** librbd refuses to create an image in a pool-snapshot-mode pool.
7. **Q5 resolved:** WRITE of length 0 creates a missing object (size 0) and extends an object when the offset is past its end; ZERO and TRUNCATE on a missing object do not create it; a ZERO that reaches the object end is rewritten to TRUNCATE in the reply.
8. **Q4 resolved:** outputs of the ops before a failing op are delivered; `FAILOK` leaves the request result 0 with the op's negative rval kept and later ops executed.

Confirmed without change: the feature bit values and incompatible masks (2.8), the op vectors A, B and C and their order (2.6), the layouts of every `rbd` and `lock` method in 2.3 and 2.7 (all decoded exactly, no trailing bytes), the omap keys (2.4), the snapshot context rules (2.5), data object names and the default and striped mappings against real objects (2.1.1, 2.9, 2.10), the data pool prefix, `get_stripe_unit_count` -ENOEXEC, the lock example bytes, the `auto <handle>` cookie, the foreign data writes, and the OSD op semantics of 2.11 that the probe exercised.

Items the captures cannot settle, and why:

| Item | Why it stays open |
| --- | --- |
| Legacy (marker 0) `entity_addr_t` form inside `locker_info_t` (2.7, Q15) | needs a client that does not advertise MSG_ADDR2; every client available here does |
| Atomicity of the multi-op header read against a concurrent header update (3.2, Q16) | a capture shows one reply, not a race |
| Flush (3.7) | no OSD op was seen after the last write of `rbd bench`, but whether the tool flushed is unknown |
| krbd behaviour, `rbd map` with a foreign lock (3.9, Q3) | kernel client, may wedge I/O in the lab VM; kernel source not in the tree |
| Journaling reader semantics (4.2) | needs a crashed journaling writer and the replay code |
| Stale snapshot context cases, `ORDERSNAP` (3.6, T12) | not run; only the fresh-context case was captured |
| `EOLDSNAPC`, `EBLOCKLISTED` numeric values (1.4) | not provoked |
| `WRITEFULL` for a whole-object librbd write, `GETXATTR`, `WRITESAME`, `CMPEXT`, discard mapping (3.7) | no capture of such I/O; op codes other than READ, STAT, SPARSE_READ, WRITE, WRITEFULL, TRUNCATE, ZERO, DELETE, CREATE, SETALLOCHINT, CALL, WATCH were never seen |
| Namespaces (2.1.2, Q8), erasure-coded data pools (Q7), `operations` / non-primary / dirty-cache images (2.8), `rbd_trash` of a trashed image (Q9), Reef / Squid differences (Q12) | no such object exists on the lab cluster |
| Multi-extent `SPARSE_READ` with a real hole (2.11) | only fully written extents were captured |
| T11 discard behaviour of the stock tools | not run |

Status of the test vectors of section 5: T1, T2, T3, T4 (all methods of 2.3 plus errors), T5 (open sequence), T6, T8, T10 (with the hole), T13, T16, T17, T18, T19 and T20 are covered by gt4, the Phase 0 captures or the probe, and by the files in `harness/vectors/rbd/`; T7 is covered for the cookie / watch handle (the `listwatchers` side was not run); T9 and T12 are covered for the librbd write side (striped mapping on the wire and real object sizes, fresh snapshot context); T14 for 0x01, 0x05, 0x21, 0x25, 0x45, 0x3D, striped, data pool, clone, migrating (0x200); T15 for stock librbd (3.9) but not krbd; T11 is open.

---

## 7. Licensing questions

1. The tables in section 2 describe field order, sizes, names and numeric constants that were read from LGPL-2.1 headers and sources of Ceph. They are protocol facts needed for interoperability and are written here in original wording. Please confirm that using these facts in the MIT-licensed core is acceptable under the project's independent-implementation rule, in particular for the feature-bit values (`src/include/rbd/features.h`), the method and class names, the omap key names, and the lock record layout.
2. The striping math in 2.10 re-expresses the algorithm of `src/osdc/Striper.cc` as pseudo-steps. The same mapping is documented in prose in `doc/dev/file-striping.rst` and `doc/architecture.rst`. The implementer should work from those documents and from the worked examples, not from the source, if the project wants the stricter position.
3. The op code values in 2.11 are computed from the macro table in `src/include/rados.h` (a mode, a type and an index); the table itself is not reproduced, only the values the core needs. Whether numeric constants from an LGPL header may be listed in an MIT file is the same question as item 1.
4. The refusal-reason identifiers in 4.6 are this project's own names.
5. Several statements describe the behaviour of the Linux kernel RBD driver; they come from Ceph's own manual page, not from the kernel source. No kernel code was consulted.
