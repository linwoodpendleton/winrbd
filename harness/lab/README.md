<!-- SPDX-License-Identifier: MIT -->
# Test lab: one disposable Ceph cluster in one VM

This directory builds the Ceph side of the winrbd test environment: a single
QEMU/KVM virtual machine running a single-host Ceph cluster deployed with
cephadm. It is meant to be abused (kill OSDs, kill the mon, reboot it) and
rebuilt in minutes. **Never point it at, or reuse, a cluster that holds data
you care about.**

Contents:

| File | Runs on | Purpose |
| --- | --- | --- |
| `lab.conf.example` | | every setting, with defaults |
| `make-vm.sh` | VM host (Linux, KVM) | download and verify the base image, create disks and cloud-init seed, start / stop the VM |
| `guest-packages.sh` | inside the VM | podman, cephadm, ceph-common, tcpdump, tshark, build tools |
| `bootstrap-ceph.sh` | inside the VM | cluster, 3 OSDs, test pool, pool-limited cephx user, two test images |
| `krbd-compat.sh` | inside the VM | lets the lab cluster accept legacy AES cephx keys so the Linux kernel client can authenticate (see below) |
| `krbd-check.sh` | inside the VM | oracle check: krbd map, pattern write / read back, unmap |
| `collect-facts.sh` | inside the VM | version and configuration facts for the protocol work (no keys) |
| `teardown.sh` | VM host | stop the VM and delete what the lab created |

## Design

```
  VM host (Linux, /dev/kvm)
  +--------------------------------------------------------------+
  |  qemu (one process, optionally a transient systemd unit)     |
  |                                                              |
  |   guest: Ubuntu 24.04 cloud image, cephadm single host       |
  |     vda  root (qcow2 overlay on the verified base image)     |
  |     vdb  cloud-init seed                                     |
  |     vdc.. data disks, one per OSD (sparse qcow2)             |
  |                                                              |
  |     inet0  <-- NIC1: user-mode (slirp) NAT, internet only    |
  |                      host 127.0.0.1:<ssh port> -> guest :22  |
  |     lab0   <-- NIC2: private L2 (QEMU multicast socket)      |
  |                      10.77.0.10/24 = Ceph public network     |
  +--------------------------------------------------------------+
```

* **One VM.** Ceph needs three OSDs for a size-3 pool; they are three virtual
  disks of the same VM, so the failure domain in the CRUSH rule is `osd`.
  Killing an OSD or the mon is `systemctl stop` or `cephadm` inside the guest.
* **No host networking is touched.** NIC1 is QEMU's built-in user-mode network:
  the guest reaches the internet through the host's normal route, and the only
  inbound path is one TCP forward bound to the host's loopback address (SSH).
  NIC2 is a virtual Ethernet segment implemented by a QEMU multicast socket
  (`-netdev socket,mcast=...,localaddr=127.0.0.1`): no bridge, tap device,
  route, firewall rule or sysctl is created on the host.
* **Cluster.** `cephadm bootstrap --single-host-defaults` with the monitoring
  stack and dashboard skipped; one mon, one mgr, one OSD per data disk. The
  container image is checked against the upstream registry's manifest digest
  before bootstrap.
* **Test pool.** `winrbd`: replicated, size 3 / min_size 2, its own CRUSH rule
  (`winrbd_osd`, failure domain `osd`), `pg_num` fixed at 32 with the
  autoscaler off so object placement is reproducible.
* **Test user.** `client.winrbd` with `mon 'profile rbd'` and
  `osd 'profile rbd pool=winrbd'` only. Its keyring is written to
  `/etc/ceph/ceph.client.winrbd.keyring` (mode 0600) in the guest. Copy it to
  the machine that runs the harness yourself; never commit it.
* **Key types (important).** A fresh Ceph 20.x cluster issues AES-256 "krb5"
  cephx keys (32-byte secret, `auth_allowed_ciphers aes256k`) and refuses to
  create or accept the legacy 16-byte AES keys. The kernel client of the
  Ubuntu 24.04 guest (6.8) rejects such a secret (`libceph: secret too big 32`),
  so krbd cannot log in to the cluster as bootstrapped. `krbd-compat.sh`
  therefore relaxes the **lab** cluster to accept both, mutes the resulting
  `AUTH_INSECURE_*` health checks, and creates `client.winrbd-aes` (same
  pool-limited caps, legacy key). Use `client.winrbd` (modern key) for what a
  default cluster looks like, and `client.winrbd-aes` for anything that goes
  through krbd. `collect-facts.sh` output taken before the relaxation is worth
  keeping as the "fresh cluster defaults" record.
* **Test images.** `winrbd/img-v1` (4 GiB, feature `layering` only) and
  `winrbd/img-default` (4 GiB, the cluster's default feature set) for
  comparison.
* **Oracle.** The guest has `ceph-common` of the same release and the `rbd`
  kernel module, so `rbd map` (krbd) is available for ground truth, with
  `tcpdump` / `tshark` for captures. `krbd-check.sh` exercises both
  `ms_mode=crc` and `ms_mode=secure`.

## Quick start

On a Linux host with KVM, `qemu-system-x86`, `qemu-utils` and `cloud-image-utils`
(or `genisoimage`) installed:

```sh
cd harness/lab
cp lab.conf.example lab.conf          # edit LAB_DIR, LAB_SSH_PUBKEY_FILE, mirrors
./make-vm.sh up                       # downloads, verifies, creates, starts
./make-vm.sh ssh                      # (on the VM host) wait for cloud-init, then log in

# copy this directory into the VM, then inside it:
sudo ./guest-packages.sh
sudo ./bootstrap-ceph.sh
sudo ./collect-facts.sh /root/facts-fresh   # defaults, before relaxing key types
sudo ./krbd-compat.sh
sudo ./krbd-check.sh
sudo ./collect-facts.sh
```

`make-vm.sh` writes everything below `LAB_DIR` (default
`~/.local/share/winrbd-lab`), never into this git tree. It refuses to run
when `LAB_DIR` already holds a running VM or existing disks, when the
filesystem has less than `LAB_MIN_FREE_GB` free, and it never overwrites a
disk. `make-vm.sh cmdline` prints the exact qemu command line.

### Reaching the VM from elsewhere

The SSH forward listens on the VM host's loopback only. From your workstation,
use the host as a jump host:

```sh
ssh -J <user>@<vm-host> -p 22221 lab@127.0.0.1
```

The login user (`LAB_SSH_USER`, default `lab`) has your public key and
passwordless sudo; no password exists.

## Adding more VMs to the private L2

Any other QEMU VM on the **same host** joins the private network with the same
multicast group and its own MAC and address:

```
-netdev socket,id=lab,mcast=230.77.0.1:7701,localaddr=127.0.0.1
-device <nic-model>,netdev=lab,mac=52:54:00:77:00:<unique>
```

(`<nic-model>` is `virtio-net-pci` for Linux, `e1000e` for a Windows guest
without virtio drivers, or whatever the test needs.) Give it an address in
`10.77.0.0/24` other than `10.77.0.10`, or let a DHCP / TFTP server (dnsmasq)
inside the lab VM serve the segment for PXE tests. The Ceph public network is
this segment, so a client on it reaches the mon at `10.77.0.10` (msgr2 port
3300, msgr1 6789) and the OSDs directly.

Notes:

* The segment exists only on one host; VMs on other hosts cannot join it.
* QEMU delivers a sender's own frames back to it, so packet captures on a
  guest NIC show every transmitted frame twice. The guest kernel ignores the
  echo; filter on direction when comparing captures.
* It is a plain Ethernet broadcast domain: no DHCP server is running unless
  you start one.

## Tear down

```sh
./teardown.sh                    # dry run: shows what would be removed
./teardown.sh --yes              # stop the VM, remove disks / seed / logs
./teardown.sh --yes --purge-images   # also the downloaded base image
./teardown.sh --yes --purge-all      # also facts/ and LAB_DIR if it is empty
```

Only fixed, known file names inside `LAB_DIR` are removed, and only when the
marker file `LAB_DIR/.winrbd-lab` exists.

To rebuild the cluster only (keep the VM), stop the Ceph daemons with
`cephadm rm-cluster --force --zap-osds --fsid <fsid>` inside the guest and run
`bootstrap-ceph.sh` again.

## Security

The lab is a throwaway. Cluster admin and `client.winrbd` keys live only inside
the VM unless you copy them out. Do not publish them, captures that contain
them, or the contents of `LAB_DIR`.
