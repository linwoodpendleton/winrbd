<!-- SPDX-License-Identifier: MIT -->
# Phase 2 lab cluster: a dedicated Ceph v20.2.5 VM for the live tests of the iPXE driver

The live tests of the iPXE driver boot QEMU guests whose firmware reads its disk from an RBD image. For that the
guests need a real cluster **on a layer 2 they can join**: the monitor is `10.77.0.10:3300`, and the OSD addresses are
*learned from the OSD map*, so the guest must reach every address the map advertises. This directory builds that
cluster as one small VM on the same Linux machine that runs the guests, with the repository's own `harness/lab`
scripts, and provides the helpers the tests need (throwaway cephx users, test images, a reachability probe). Design
and the options that were weighed (a relay through jump hosts, QEMU TCG inside the main lab VM): section 14.1 of
`docs/design/ipxe-driver.md`; this is option C there.

It is a throwaway. **Never point it at a cluster that holds data you care about**, and never reuse the keys.

| File | Purpose |
| --- | --- |
| `lab.conf.example` | every setting, with the values used on the shared build machine |
| `up.sh` | create what is missing and start the lab VM; idempotent. Also `status`, `stop`, `env`, `ssh`; and the function library of the other scripts |
| `down.sh` | stop the VM and delete exactly what the scripts made |
| `users.sh` | throwaway cephx users (legacy `aes` keys), test images <= 4 GiB, extra pools, a krbd check |
| `probe.sh` | boot a small guest on the lab's layer 2 and show that it reaches the monitor and the OSDs |
| `selftest.sh` (+ `selftest_iso.py`) | offline test of all of the above with stand-ins for `ps`, the VM and the Ceph commands: no VM, QEMU, ssh or network |

All scripts take `-n` / `--dry-run` (print what would be run, change nothing). All are `shellcheck` clean, and `selftest.sh` (below) passes.

## Layout

```
  the Linux build machine (KVM, no root needed, nothing on its network is touched)
  +----------------------------------------------------------------------------+
  |  LAB_DIR  (its own directory, marked by .winrbd-lab; nothing else is touched)  |
  |    images/  base image (Ubuntu 24.04 cloud image, sha256 verified)            |
  |    vm/      root.qcow2 (30 GiB, sparse), osd0..2.qcow2 (12 GiB, sparse),     |
  |             seed.iso, console.log, qemu.pid, qmp.sock                         |
  |    ssh/     key pair of this lab (mode 700 / 600)                             |
  |    keys/    keyrings and secrets of the throwaway users (mode 700 / 600)     |
  |    logs/ state/ tools/ probe/ facts/                                          |
  |                                                                               |
  |  lab VM  (nice -n 19 choom -n 600 --)   8 GiB, 4 vCPU, KVM                    |
  |    NIC 1  user-mode (slirp): internet for apt / registry; 127.0.0.1:22232 -> :22 |
  |    NIC 2  QEMU multicast socket 230.77.12.1:7712 on 127.0.0.1                  |
  |           10.77.0.10/24 = the Ceph public network: mon 3300 (v2) / 6789 (v1),   |
  |           3 OSDs, mgr; single host, failure domain osd, pool winrbd           |
  |                                                                               |
  |  test guests (any other QEMU on this machine)                                  |
  |    NIC 1  user-mode (slirp): PXE bootfile / DHCP                              |
  |    NIC 2  -netdev socket,mcast=230.77.12.1:7712,localaddr=127.0.0.1           |
  |           static 10.77.0.x (x = 20..99; 50 is the probe guest)               |
  +----------------------------------------------------------------------------+
```

* **Isolation from every other lab.** The multicast group (`230.77.12.1:7712`), the MAC addresses
  (`52:54:00:77:12:xx`) and the SSH port (22232) all differ from the defaults of `harness/lab` (`230.77.0.1:7701`,
  `52:54:00:77:00:xx`, 22221), and `up.sh` refuses to start when another QEMU process on the machine already uses
  the group or one of the MACs, or when the port is taken. The segment exists only inside this machine's loopback:
  no bridge, tap device, route, firewall rule or sysctl is created, and no process listens on anything but
  `127.0.0.1`. The Ceph addresses are the same as in the main lab (`10.77.0.0/24`) on purpose: the two layers 2 can
  never see each other.
* **Size.** 4 vCPU, 8 GiB, three sparse OSD disks of 12 GiB (a maximum, not a reservation), a sparse 30 GiB root.
  With three OSDs, a mon and a mgr in 8 GiB the default `osd_memory_target` of 4 GiB each does not fit, so `up.sh`
  pins it (`P2_OSD_MEMORY_TARGET`, 1.2 GiB) and turns the cephadm autotuner off.
* **Budget.** The whole Phase 2 workflow may use 24 cores and 32 GiB of RAM at any time. `up.sh` and `probe.sh` add
  up the `-smp` and `-m` of every QEMU process whose command line is below the parent directory of `LAB_DIR` and
  refuse to start a VM that would exceed it (`P2_BUDGET_CORES`, `P2_BUDGET_MEM_MB`). That makes the parent of `LAB_DIR` the
  scope of the budget: put `LAB_DIR` directly below the directory that holds every VM of the workflow (on the shared build
  machine `.../winrbd/lab-p2`, not `.../winrbd/p2/lab`), or the other VMs are not counted. The converse also holds: a VM of someone else under the same parent is counted too
  (a left-over CI VM of 12 GiB made `probe.sh` refuse on the shared machine, correctly by the numbers); when that VM is not
  part of this workflow, raise `P2_BUDGET_MEM_MB` / `P2_BUDGET_CORES` for that one run by exactly its share and say so. Planned shares: the lab VM
  4 cores / 8 GiB, a build VM 8 / 12 GiB, one test guest 2 to 4 cores. Every process the scripts start runs as
  `nice -n 19 choom -n 600 --`; `up.sh` reads the VM's nice value and `oom_score_adj` back from `/proc` and stops it if
  they are not as required.
* **No KVM, no lab.** `/dev/kvm` must be usable by the calling user; a lab in TCG emulation would be too slow to be a test.

### What is built, and with what

`up.sh` only orchestrates; the lab itself is built by the repository's scripts:

1. `harness/lab/make-vm.sh prepare` downloads the Ubuntu 24.04 cloud image and verifies it against the published
   `SHA256SUMS`, creates the disks and the cloud-init seed.
   *The box has no `cloud-localds` / `genisoimage`*, which `make-vm.sh` needs for the seed, and no root to install
   them, so `up.sh` puts a stand-in named `cloud-localds` on `PATH` for that one call (`LAB_DIR/tools/bin`, about
   140 lines of Python standard library: an ISO 9660 image with a Joliet tree and the volume label `cidata`).
   `make-vm.sh` itself is not modified.
2. `make-vm.sh start` under `nice -n 19 choom -n 600 --` (a plain `-daemonize` background QEMU with a pidfile).
3. inside the VM, as root, in this order (each runs detached and is polled, so a dropped SSH connection loses
   nothing; a marker per stage makes a re-run skip it): `guest-packages.sh` (podman, cephadm, ceph-common 20.2.5,
   tools), `bootstrap-ceph.sh` (single-host cluster, three OSDs, pool `winrbd`, `client.winrbd`, `img-v1`,
   `img-default`), `krbd-compat.sh` (accept legacy `aes` keys, create `client.winrbd-aes`), then the memory tuning.
4. mute the health checks that are expected here (below), wait for `HEALTH_OK`, and check that **every monitor and OSD address in the maps is inside `10.77.0.0/24`**
   (a daemon that bound to the slirp address would be unreachable from a guest on the layer 2).

**Health checks muted on purpose (sticky mutes):** `AUTH_INSECURE_*` (the lab accepts legacy keys, see below) and
`BLUESTORE_SLOW_OP_ALERT` (the VM runs at nice 19 on a busy machine, so its sparse disks are slow after each boot and Ceph
keeps that warning for 24 hours). Operations that really hang still raise `SLOW_OPS`. `users.sh` re-applies the mutes after
every change, because a plain mute is dropped when its check clears.

Re-running `up.sh` is safe: a running VM is left alone, a stopped one is started, finished stages are skipped, and
the checks run again. `bootstrap-ceph.sh` is **not** restartable (it refuses when a cluster exists); if a stage fails
`up.sh` says so, and the way out is `down.sh`, then `up.sh`.

## Using it

On the machine that hosts the lab (every script finds `harness/lab` relative to itself):

```sh
export LAB_DIR=$HOME/work/winrbd-p2-lab     # must not exist yet, or be empty; below your own work directory
cd harness/lab/p2/cluster
./up.sh -n          # look first
./up.sh             # first time: 1 to 2 hours on a busy shared machine (600 MB image, ~330 MB of apt packages, a
                    # 1.3 GB container image, all at nice 19); a nearby mirror (LAB_APT_MIRROR, LAB_CEPH_IMAGE) shortens it
./up.sh status
./up.sh stop          # power the VM off, keep the cluster; ./up.sh starts it again (about 3 minutes)
./probe.sh
./users.sh create wrtest-p2-u0 --size 2G   # image + user + key files
./users.sh krbd-check wrtest-p2-u0
./users.sh delete wrtest-p2-u0
./down.sh           # leaves nothing behind
```

From another machine (a workstation): copy `harness/lab` here (`rsync -R harness/lab/*.sh harness/lab/p2/cluster/
user@box:work/winrbd-p2-src/`) and run the scripts over `ssh` (add a jump host with `-J` if needed); the lab VM is only ever
reached from the box itself (`127.0.0.1:22232`), never from outside.

`eval "$(./up.sh env)"` defines, without any secret, what a script that starts guests needs: `P2_MCAST`,
`P2_MCAST_LOCALADDR`, `P2_MON_ADDR`, `P2_MON_PORT`, `P2_NET_CIDR`, `P2_POOL`, `P2_KEYS_DIR`, `P2_BASE_IMAGE`,
`P2_SSH_PORT`, `P2_SSH_KEY`, `P2_BUDGET_*`. `./up.sh ssh [CMD...]` runs a command in the VM.

A test guest joins the layer 2 with two NICs; NIC 2 is

```
-netdev socket,id=lab,mcast=230.77.12.1:7712,localaddr=127.0.0.1
-device virtio-net-pci,netdev=lab,mac=52:54:00:77:12:<unique>
```

(`e1000e` for a guest without virtio drivers, e.g. Windows; `virtio-net-pci` for Linux). It needs a static address in
`10.77.0.0/24` other than `.10` and `.50`; no DHCP server runs on the segment. QEMU delivers a sender's own frames
back to it, so captures on a guest NIC show every transmitted frame twice.

### Throwaway cephx users (`users.sh`)

One user per test image, created for the run and deleted afterwards:

* name `wrtest-p2-<name>` (or any `wrtest-...`), image of the same name in pool `winrbd` (or a `wrtest-*` pool), at
  most 4 GiB (default 2 GiB). Everything created has the prefix `wrtest-`; `delete` / `delete-all` touch nothing
  else (never `img-v1`, `img-default`, `client.winrbd`, `client.winrbd-aes`, the pool `winrbd`).
* caps: `mon 'profile rbd'`, `osd 'profile rbd pool=<one pool>'`. `krbd-check` proves the limit: with the user's own key
  an `rbd ls` of another pool is refused **with a permission error** (a timeout or a missing pool is a failure, not a pass).
* key type: **legacy `aes`** (16-byte secret) by default, because the Linux kernel client in a guest rejects the 32-byte
  `aes256k` keys a fresh Ceph 20 cluster issues (`libceph: secret too big 32`; see `harness/lab/README.md`). The
  cluster accepts both thanks to `krbd-compat.sh`; `--key-type aes256k` makes a modern one for the iPXE side.
* an existing user of the same name is reused only when its `osd` caps are exactly `profile rbd pool=<pool>` (else the
  script stops and says to delete it first), and after `create` the key size is read back (the decoded blob, never the
  key): a key of another type than requested is an error, so a test never runs with a key it does not believe it has.
* the keyring and the bare secret land in `LAB_DIR/keys/client.<name>.keyring` / `.secret`, **mode 600, in a directory
  of mode 700, never printed**: the scripts discard the command output that carries a key, print only the path, and
  `down.sh` removes the directory. They are never committed (the directory is outside the git tree). The boot script a
  test generates from them goes into a scratch directory of its own.
* `krbd-check` maps the image inside the VM **with the user's key only** (the keyring is written to a file in RAM
  and removed on exit), writes a random MiB at the start and at the end of the image, reads both back with
  `O_DIRECT`, compares with `rbd export`, checks the key size (28 bytes decoded = legacy), tries another pool, unmaps.

`users.sh pool-create NAME` / `pool-delete NAME` make and remove an extra pool `wrtest-p2-NAME` (`wrtest-NAME` when NAME already starts with `wrtest-`) (8 PGs, replicated, size 3,
on the lab's `winrbd_osd` rule; deletion is enabled only for the instant of the delete). `list` shows users, images,
pools and key files (names and modes).

### The probe (`probe.sh`)

`probe.sh` answers "can a guest on the layer 2 reach the cluster the way the driver will?":

1. asks the VM for the msgr2 address of the monitor and of every OSD (`ceph mon dump`, `ceph osd dump`);
2. boots a small guest (copy-on-write overlay of the verified base image, 1 core, 768 MiB, under `nice` / `choom`):
   NIC 1 user-mode, NIC 2 on the multicast group with the static address `10.77.0.50`;
3. the guest (first-boot script, results on its serial console) prints the link and address of NIC 2, the route the
   kernel chooses to the monitor (it must be `dev lab0`, i.e. the layer 2, not the slirp NIC), the neighbour table,
   then opens a TCP connection to every address and reads the first 8 bytes. A msgr2 peer sends `ceph v2` first, so this
   is the daemon answering, not merely a port that accepts. One address nobody owns (`10.77.0.99:3300`) is tried as a
   **control** and must not answer;
4. the guest powers itself off, the script prints a table, keeps the result and console log in `LAB_DIR/logs`, removes
   the guest's files, and exits 0 only when the guest finished, the route to the monitor used the private NIC, the guest
   probed **exactly** the monitors and OSDs the maps advertise (a skipped target is a failure), every one answered with
   the banner, and the control did not. An OSD that is down has no address to reach and is not in the list.

## Tests

`./selftest.sh` runs offline in about a minute (one process per case, so each case has its own `set -e`): the machine's
`ps`, the VM and the Ceph commands are stand-ins, and everything it creates is below one temporary directory that it
removes. It covers the isolation check (a foreign VM on the group or on one of the MACs is refused and the pid is
named; the lab's own VM, the probe guest, near misses such as a longer port, and processes that only mention QEMU are not
counted), the budget arithmetic, the address check (empty answer, no monitor, too few OSDs, an address outside the
network), the probe verdict (a missing banner, an unreachable OSD, an answering control, a skipped target, no END line,
the wrong NIC), `users.sh` validation and secret handling (a fake key that the stand-in `ceph` returns must never appear
in any output, also on failure paths; key files mode 600 in a 700 directory), `down.sh` (a directory without the marker
is refused, only the tool's own files are deleted, foreign files are left and reported), dry runs (they create nothing),
and the `cloud-localds` stand-in (`selftest_iso.py` parses the image back: volume label, Joliet names, exact contents).

The live proof is `up.sh`, then `probe.sh`, then `users.sh create` + `krbd-check` + `delete`, then `down.sh`.

## Tear down

`down.sh` stops a leftover probe guest, stops the lab VM (ACPI power-off, then terminate), deletes the files of this
tool (stand-in, SSH key pair, key files, logs, state, probe leftovers, `known_hosts`, the lock), then runs
`harness/lab/teardown.sh --yes --purge-all` (VM disks, seed, console log, base image, facts, the marker) and removes
`LAB_DIR` when it is empty; anything left is listed and the exit status is 1. Only fixed names are removed, never a
recursive delete of a variable, and nothing without the marker file `LAB_DIR/.winrbd-lab`. `--keep-image` keeps the
downloaded base image (about 600 MB) for the next `up.sh`.

## Settings

See `lab.conf.example`. The file used is `$LAB_CONF`, else `lab.conf` next to the scripts, else the example as it is;
`LAB_*` and `P2_*` environment variables win over the file. A private `lab.conf` in this directory is **not** covered by
the repository's `.gitignore` (which lists only `harness/lab/lab.conf`): keep yours outside the tree.

## Security

* The lab's admin keyring exists only inside the VM; the throwaway users' keys only in `LAB_DIR/keys` (mode 600) and
  in the cluster. Do not publish captures that contain them. The SSH key pair of the lab is created per `LAB_DIR`
  with no passphrase, mode 600, and removed by `down.sh`; the VM accepts nothing else and no password exists.
* The VM is reachable only through `127.0.0.1:22232` of the machine that runs it. The monitor and OSDs listen on the
  private layer 2 only, which has no gateway.
* The cluster is relaxed on purpose (legacy `aes` keys allowed, `AUTH_INSECURE_*` health checks muted) so that the
  Linux kernel client can be used as an oracle. Do not do this on a cluster you care about.
