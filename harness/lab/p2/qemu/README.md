# Phase 2 QEMU scripts: boot the iPXE `rbd://` driver in OVMF and SeaBIOS

These scripts run **one QEMU guest per run** to answer one question of the matrix in `docs/design/ipxe-driver.md`
section 14.3: *does this firmware, started this way, boot through the `rbd://` SAN driver?* They talk to a lab cluster
(`harness/lab/p2/cluster`, section 14.1 option C) over a private layer 2 that QEMU itself makes; nothing on the host's
network is touched.

| File | What it is |
|---|---|
| `run-uefi-pxe.sh` `run-uefi-usb.sh` `run-uefi-iso.sh` | rows U1 / U2 / U3: OVMF (Secure Boot off), booted over PXE / from a USB stick / from a CD |
| `run-bios-pxe.sh` `run-bios-usb.sh` `run-bios-iso.sh` | rows B1 / B2 / B3: SeaBIOS, the same three ways |
| `gen-script.sh` | the iPXE run script of one run (finds the lab NIC, sets the address, the key, `sanhook` / `sanboot`, prints `WRRUN-*` markers), the constant PXE stub (`--stub`) and the constant driver smoke script (`--smoke`) |
| `make-usb.sh` | the USB stick (GPT + FAT, or a hybrid CD image) and the CD (BIOS + EFI El Torito) around an iPXE binary and the script |
| `common.sh` | the library every run script sources: options, limits, firmware, NICs, media, serial log and markers, timeout, clean-up |
| `smoke.sh` | the six rows without a cluster: firmware starts iPXE, iPXE runs the script, the lab NIC is there, and the skeleton's driver test (password refused, a well-formed URI fails closed, unknown scheme control, `SMOKE-DONE`); `--san` and `--hold` add the failing-target and the negative-control passes |
| `selftest.sh` | offline self-test (QEMU stand-in, no KVM, no cluster); `--quick` starts no process |

The rows U0 and B0 of the matrix are the same scripts with other defaults (`--row U0`: the script leaves, the run takes OVMF to its
UEFI shell and types `map -r;fs0:;ls`; `--row B0`: `sanhook --drive 0x81` next to a local disk, `--disk FILE`). OVMF does **not** start
its shell by itself: when every boot option has returned it stops in its setup menu, which is drawn on the screen only. Row U0
therefore presses keys through QMP ten seconds after `WRRUN-END`: Down Down Enter (Boot Manager), then Down to "EFI Internal
Shell" and Enter (`--menu-keys`; the number of boot entries in front of the shell is 4 for the PXE rows, 1 for a stick or a CD).
It is blind, so a run that does not reach `Shell>` keeps a screenshot of what OVMF shows (`logs/<run>.screen.ppm`). The WinPE rows W1 to W4 are
the same scripts with a WinPE image on the RBD image: **they need a WinPE image from the owner** (section 14.3: there is no
legal, redistributable way to get one here); `harness/lab/p2/winpe` prepares and checks the layout.

## What a run needs

* a KVM host with `qemu-system-x86_64` and `python3`; for the UEFI rows OVMF (`OVMF_CODE_4M.fd`, the Secure-Boot-off
  `OVMF_VARS_4M.fd`; `P2Q_OVMF_CODE` / `P2Q_OVMF_VARS` name others; a Secure Boot build is refused);
* the iPXE binaries from `ipxe/tools/build.sh`, in `$P2Q_WORK/ipxe` or `--ipxe-dir`:

| Row | Binary | How the script reaches iPXE |
|---|---|---|
| U1 | `ipxe.efi` | iPXE for EFI asks the TFTP server for `autoexec.ipxe` next to the file it was loaded from |
| U2 | `ipxe.efi` as `EFI/BOOT/BOOTX64.EFI` | `autoexec.ipxe` at the root of the stick |
| U3 | `ipxe.efi` (and `ipxe.lkrn`: one image serves B3 too) | `autoexec.ipxe` at the root of the El Torito EFI image |
| B1 | `ipxe-stub.pxe` = `ipxe.pxe` built with the stub (see below) | a BIOS iPXE started by PXE reads **no** `autoexec.ipxe` by itself: the stub fetches it over TFTP |
| B2 | `ipxe.lkrn` | isolinux starts it with the script as its initrd, which iPXE takes as its script |
| B3 | `ipxe.lkrn` | the same, from the CD |

  A BIOS build must have a **serial console** or these scripts see nothing from it (stock iPXE for BIOS has only the VGA
  console, and the run scripts read the serial line): build it with `-- EXTRA_CFLAGS=-DCONSOLE_SERIAL`. The stub is built into
  the binary once: `gen-script.sh --stub -o stub.ipxe`, then `ipxe/tools/build.sh build -e stub.ipxe bin/ipxe.pxe -- EXTRA_CFLAGS=-DCONSOLE_SERIAL`
  (copy the result to `ipxe-stub.pxe`). Use `ipxe.pxe`-style native drivers, **not** `undionly.kpxe`, for any run that needs the
  cluster: UNDI drives only the NIC PXE booted from, and the lab NIC (NIC 2) is invisible to it (`WRRUN-NO-LAB-NIC`).
  `undionly.kpxe` is fine for "reaches iPXE" checks.
* for `make-usb.sh`: `mtools`, `python3`, `xorriso`, and the syslinux files (`isolinux.bin`, `ldlinux.c32`, `isohdpfx.bin`); an
  unpacked package prefix is found through `P2Q_TOOLS` (default `$P2Q_WORK/tools/usr`).
* the lab cluster up (`harness/lab/p2/cluster/up.sh`) and a cephx user for the image (`users.sh`); the key goes in a mode-600 file.

## A run

```
export P2Q_WORK=$HOME/winrbd-p2-qemu          # run directories, logs, iPXE binaries (ipxe/), tools (tools/)
run-uefi-pxe.sh -n --pool winrbd --image uefi-gpt --user wrp2 --key-file ~/wrp2.key   # look first: nothing is started
run-uefi-pxe.sh    --pool winrbd --image uefi-gpt --user wrp2 --key-file ~/wrp2.key --expect san
run-uefi-pxe.sh    --pool winrbd --image uefi-gpt --user wrp2 --key-file ~/wrp2.key --action sanboot --expect os --timeout 600
smoke.sh --san --hold                           # all six rows, no cluster: reaches iPXE, the driver test, the failing target, the negative control
```

* `--expect` names the stage that makes the run a success: `ipxe` (iPXE ran the whole script), `san` (the `sanhook` worked;
  the default when a target is given), `os` (the booted OS printed a line starting `WRBOOT-ROOT-OK`, or `--ok-marker`; the image's other verdicts `WRBOOT-ROOT-NOT-RBD` / `-TABLE-FAIL` / `-WRONG` and a kernel panic end the run at once as `stop=fail-marker`, unless `--fail-marker` says otherwise), `shell` (UEFI
  shell prompt, row U0), `marker` (a line matching `--marker`, for negative tests: `--marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+'`),
  `none` (never; with `--stay`: wait for the guest or the timeout). A failed SAN open (`stop=san-failed`) or a lab NIC that is missing or has no link
  (`stop=net-failed`) ends a `san` / `os` run at once instead of waiting out the timeout. A guest whose serial log passes `P2Q_CONSOLE_MAX_MB` (default 64)
  is stopped (`stop=console-flood`): a panic loop must not fill the disk.
* The last line on stdout is always `RESULT row=... expect=... met=0|1 ipxe=<s> net=<s> san=ok|failed@<s> end=<s> os=<s> stop=... secs=... console=<log>`
  (seconds since the start of the guest at which each stage was first seen). Exit status: **0** the expected stage was reached,
  **1** it was not (timeout, the guest ended first, a failure marker), **2** usage or environment (nothing was started, or QEMU would
  not start), **4** something was left behind or the key was found in a log.
* The serial console is the only channel: the script's `WRRUN-*` lines, iPXE's own output, the UEFI shell, the guest's
  kernel. A screenshot of a guest that missed its stage is kept next to the log (`P2Q_SCREENDUMP=0` turns it off).
* Error numbers are printed as `0x<iPXE error number>` (for example `WRRUN-SAN-FAILED 0x3c2d0539`).

## The real build targets (`bin/ipxe.usb`, `bin/ipxe.iso`)

`make-usb.sh` makes the same kind of media as iPXE's own `util/genfsimg`, but from the files of this repository's run directory. The images that
`make bin/ipxe.usb` and `make bin/ipxe.iso` build can be run too: build them with the script embedded (`ipxe/tools/build.sh build -e SCRIPT bin/ipxe.usb bin/ipxe.iso -- EXTRA_CFLAGS=-DCONSOLE_SERIAL`;
`genfsimg` looks for `isolinux.bin`, `mformat` and `xorriso` only in system directories, so build them where those packages are installed, for example in the Ubuntu 26.04
builder guest) and give them to a run script with `--media FILE --delivery embed`:

```
run-bios-usb.sh --media ipxe.usb --delivery embed --expect marker --marker '^SMOKE-DONE' --no-key --action none     # row B2 with the real ipxe.usb
run-bios-iso.sh --media ipxe.iso --delivery embed --expect marker --marker '^SMOKE-DONE' --no-key --action none     # row B3 with the real ipxe.iso
```

```
run-uefi-iso.sh --media ipxe-efi.iso --delivery embed --expect marker --marker '^SMOKE-DONE' --no-key --action none # row U3 with the real bin-x86_64-efi/ipxe.iso
```

`bin/ipxe.iso` is a BIOS image (isolinux only): OVMF finds nothing on it and the run ends cleanly at its timeout. The EFI CD of row U3 is `bin-x86_64-efi/ipxe.iso`.
All three real images were built warning-free (gcc 15.2, iPXE's own `-Werror`) and reach their embedded script in the guests of this module.

## The smoke test

`smoke.sh` needs no cluster and no key. Per row it runs up to four passes, each in its own guest, and the table at the end lists the seconds to every stage:

| Pass | What it proves | How it is checked |
|---|---|---|
| `reaches-ipxe` | firmware starts the iPXE binary, iPXE finds the run script, the lab NIC (the one with the lab MAC) is there, opens and has link, iPXE leaves | `WRRUN-BEGIN` and `WRRUN-END` on the serial line |
| `driver` | the skeleton's firmware test, `gen-script.sh --smoke`: a URI with a password is refused with the driver's own line `rbd: key material must not be part of the URI (use the rbd-key setting)` and `Invalid argument`; a well-formed URI to a monitor that does not exist fails closed (`failed closed: 0x...`: `Operation not supported` while opening is not implemented, a connection error later; a SAN device is never created); an unknown scheme is the control and shows iPXE's stock `Operation not supported`; the script ends with `SMOKE-DONE` | smoke.sh reads the console log and requires every line, and no `WRSMOKE-FAIL` |
| `san-fails` (`--san`) | the same failing target through the run script and the lab NIC | `WRRUN-SAN-FAILED 0x<number>`; the run stops at once, not at the timeout |
| `no-cluster` (`--hold`) | the negative control of the run scripts: nothing answers, the guest holds after the failure, and the run ends by itself at its timeout | exit status 1, `stop=timeout`; exit 4 (a process or a file left behind) would fail it |

`B1U` (added when `undionly-stub.kpxe` is in the iPXE directory, or by `--rows`) is row B1 with `undionly.kpxe`, built with the stub: UNDI drives only the NIC PXE booted from, so the lab NIC must be invisible. That row passes when the script runs and says `WRRUN-NO-LAB-NIC`; it is the proof that the PXE rows that need the cluster have to use `ipxe.pxe`. The undionly stub is built with `ipxe/tools/build.sh build -e stub.ipxe bin/undionly.kpxe -- EXTRA_CFLAGS=-DCONSOLE_SERIAL` and copied to `undionly-stub.kpxe`.

After the passes the script looks for any guest process of the work directory and fails if one is left.

## What is guaranteed (the rules of the shared build machine)

* Every QEMU runs as `nice -n 19 choom -n 600 --`, with at most 4 cores and 4 GiB per guest (defaults 2 and 2 GiB).
  Before a guest starts the scripts add up the `-smp` / `-m` of every QEMU below `P2Q_BUDGET_ROOT` and refuse to start when the
  workflow's budget (`P2Q_BUDGET_CORES` 24, `P2Q_BUDGET_MEM_MB` 32768) would be exceeded. Budget check and start are one step under a
  lock (`flock` on `$P2Q_WORK/.start.lock`): two run scripts started together cannot both pass. A guest address is used by one
  guest at a time (`--ip`, `.20` to `.99` but `.50`). **Only the QEMUs below the budget root are counted**: by default that is the
  parent directory of `P2Q_WORK` (or of `P2_LAB_DIR`), so a machine whose VMs live in other directories needs `P2Q_BUDGET_ROOT` set to
  the directory above all of them, or the budget is checked against this module's own guests only.
* Networking is user-mode (restricted: no way out to the host's network) plus one QEMU multicast-socket NIC on `127.0.0.1`.
  No tap, no bridge, no host forward, no listening socket; `--qemu-arg` refuses anything of that kind (and VNC, a gdb stub,
  a TCP monitor, shared directories, a chardev that connects out, a disk that is a network resource such as `nbd:` or `http:`).
* A guest is found again by its own name (`-name wrp2q-<row>-<time>-<pid>`) and a pid file in its run directory; only a process whose
  command line carries that name is ever signalled. TERM / INT / HUP to a run script stop its guest and remove its files.
* **The key.** It is read from a mode-600 file by `gen-script.sh`, written into the run script (one `set rbd-key` line) and
  nowhere else; it is never an argument of any program and never printed. The copies (the script, its TFTP copy, the stick /
  CD) live in the run directory (mode 700) and are deleted at the end; the console log is scanned for the key and discarded, with
  exit status 4, if it is there. `--keep` keeps the run directory for debugging: it then holds the key. A `--script` of your own is
  copied into the run directory and deleted likewise, but only the `set rbd-key <key>` line (quotes allowed) is scanned for.
* The USB stick is attached read-only; `--disk FILE` gets a qcow2 overlay unless `--disk-write`.
* `$P2Q_WORK` must be the caller's own directory (not a symbolic link, not owned by another user) and everything a run makes is mode 600 / 700
  (the scripts set `umask 077` themselves). The signal traps stay armed until the clean-up of the run has finished.
* Nothing under `$P2Q_WORK` is touched unless it carries the marker `.winrbd-p2-qemu` (or is empty, or holds only `ipxe/`,
  `tools/`, `media/`).

## Known limits

* One guest per run; the matrix runs rows one after another (or in parallel with different `--ip`, within the budget).
* The UEFI shell is driven by QMP key events (US layout); only plain characters are typed.
* `make-usb.sh bios-usb` makes a **hybrid** isolinux image (boots as a CD and as a disk) because the syslinux installer ends in a
  global `sync()` that on a busy shared machine stalled for 20+ minutes, uninterruptibly; `--method syslinux` makes the FAT stick
  of `ipxe.usb` (use it on a quiet machine). Neither is the file `make bin/ipxe.usb` builds; a ready-made `bin/ipxe.usb` with an
  embedded script runs with `--media FILE --delivery embed`.
* Nothing here measures speed: the guests run on a loaded shared machine.
