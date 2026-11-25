<!-- SPDX-License-Identifier: MIT -->
# MATRIX of the final run (2026-11-24)

One line per directory of `rows/` (made by a script from the verdict files, not typed in). `PASS` means every check of the row's profile held; `FAIL` that one did not (the line says which). The rows under `attempts` are
runs that did not count, kept with their reason in the directory name: the first WinPE import had the image's default features (the writer profile refuses them, R-5), the first UEFI-shell rows used a build with iPXE's own serial console
(`-DCONSOLE_SERIAL`: every character doubled, so no console line matched), two rows named the same option twice, one did not start while the lab was busy rolling an image back. The `loss` rows compare the
receive window of 4 MiB (`ab-old`) with 64 KiB (`ab-new`) with packet loss on the replies to the guest; the `rd-*` rows are the INT 13h read bench with four windows (`oldwin` 4 MiB, `w256`, `w128`, and the default 64 KiB `rd-def` / `rd-ra0`);
`loss8pct-new-2` and `loss8pct-old-2` booted and mapped their root (the console shows it) but are judged FAIL by the marker patterns: a later console line followed the prompt, or came after it.

| Row | Verdict | Seconds | What the row shows |
|---|---|---|---|
| `rows-N-nokey-console-serial-doubled` (attempts) | FAIL | 11 | console line /no cephx key: set rbd-key/: not in the log; the SAN open failed: no WRRUN-SAN-FAILED line (stop=guest-exited) |
| `rows-N-nomon-console-serial-doubled` (attempts) | FAIL | 26 | console line /rbd: .*failed: .*\(WR_E_(MON_UNREACHABLE|TIMEOUT|NET_CONNECT)\)/: not in the log; the SAN open failed: no WRRUN-SAN-FAILED line (stop=guest-exited) |
| `rows-N-password-console-serial-doubled` (attempts) | FAIL | 301 | console line /key material must not be part of the URI/: not in the log; the SAN open failed: no WRRUN-SAN-FAILED line (stop=timeout) |
| `rows-N-wrongimage-console-serial-doubled` (attempts) | FAIL | 12 | console line /rbd: .*failed: image not found .*\(WR_E_RBD_NOT_FOUND\)/: not in the log; the SAN open failed: no WRRUN-SAN-FAILED line (stop=guest-exited) |
| `rows-N-wrongkey-console-serial-doubled` (attempts) | FAIL | 27 | console line /rbd: .*failed: .*\(WR_E_AUTH_[A-Z_]+\)/: not in the log; the SAN open failed: no WRRUN-SAN-FAILED line (stop=guest-exited) |
| `rows-N-wrongpool-console-serial-doubled` (attempts) | FAIL | 11 | console line /rbd: .*failed: pool not found .*\(WR_E_POOL_NOT_FOUND\)/: not in the log; the SAN open failed: no WRRUN-SAN-FAILED line (stop=guest-exited) |
| `rows-U0-sata-console-serial-doubled` (attempts) | FAIL | 39 | sanhook of the image: no WRRUN-SAN-OK; the shell was started from iPXE: no WRU0-SHELL-START (no WRU0 line) |
| `rows-U0-uri-console-serial-doubled` (attempts) | FAIL | 38 | sanhook of the image: no WRRUN-SAN-OK; the shell was started from iPXE: no WRU0-SHELL-START (no WRU0 line) |
| `rows-U0-vendor-console-serial-doubled` (attempts) | FAIL | 39 | sanhook of the image: no WRRUN-SAN-OK; the shell was started from iPXE: no WRU0-SHELL-START (no WRU0 line) |
| `rows-U1-sata-console-serial-doubled` (attempts) | (none) |  | table 40/40 fields |
| `rows-U1-uri-console-serial-doubled` (attempts) | FAIL | 60 | login 60.0 s / table 40/40 fields / script used sanboot: no WRRUN-SAN-START sanboot |
| `rows-UB-bytes-console-serial-doubled` (attempts) | FAIL | 23 | file f-0001: iPXE printed no digest; file f-0511: iPXE printed no digest; file f-0512: iPXE printed no digest; file f-0513: iPXE printed no digest; file f-4095: iPXE printed no digest; file f-4096: iP |
| `rows-UB-bytes-ra0-console-serial-doubled` (attempts) | FAIL | 32 | file f-0001: iPXE printed no digest; file f-0511: iPXE printed no digest; file f-0512: iPXE printed no digest; file f-0513: iPXE printed no digest; file f-4095: iPXE printed no digest; file f-4096: iP |
| `winpe-W1-1-features-default` (attempts) | FAIL | 11 | the run script reached its expectation (met=0, stop=guest-exited); the stage 'marker' was seen (None) |
| `winpe-W1-sata-1-option-given-twice` (attempts) | FAIL | 12 | the run script reached its expectation (met=0, stop=guest-exited); the stage 'marker' was seen (None) |
| `winpe-W1-uri-1-option-given-twice` (attempts) | FAIL | 13 | the run script reached its expectation (met=0, stop=guest-exited); the stage 'marker' was seen (None) |
| `winpe-W2-1-did-not-start` (attempts) | (none) |  |  |
| `winpe-W2-1-features-default` (attempts) | FAIL | 10 | the run script reached its expectation (met=0, stop=guest-exited); the stage 'marker' was seen (None) |
| `winpe-W3-1-features-default` (attempts) | FAIL | 12 | the run script reached its expectation (met=0, stop=guest-exited); the stage 'marker' was seen (None) |
| `winpe-W4-1-features-default` (attempts) | FAIL | 3 | the run script reached its expectation (met=0, stop=guest-exited); the stage 'marker' was seen (None) |
| `B1-boot-ctl` (robust) | PASS | 60 |  |
| `B1-boot-link` (robust) | PASS | 103 |  |
| `B1-boot-mon` (robust) | PASS | 77 |  |
| `B1-boot-osd-kernel` (robust) | PASS | 78 |  |
| `B1-boot-stall20` (robust) | PASS | 91 |  |
| `B1-neg-key` (robust) | PASS | 32 |  |
| `U1-boot-ctl` (robust) | PASS | 55 |  |
| `U1-boot-link` (robust) | PASS | 102 |  |
| `U1-boot-mon` (robust) | PASS | 79 |  |
| `U1-boot-osd-kernel` (robust) | PASS | 87 |  |
| `U1-boot-stall20` (robust) | PASS | 85 |  |
| `U1-neg-image` (robust) | PASS | 18 |  |
| `U1-neg-key` (robust) | PASS | 46 |  |
| `U1-neg-mon` (robust) | PASS | 33 |  |
| `U1-neg-pool` (robust) | PASS | 18 |  |
| `N-nokey` (rows) | PASS | 12 |  |
| `N-nomon` (rows) | PASS | 46 |  |
| `N-password` (rows) | PASS | 12 |  |
| `N-wrongimage` (rows) | PASS | 12 |  |
| `N-wrongkey` (rows) | PASS | 26 |  |
| `N-wrongpool` (rows) | PASS | 12 |  |
| `U0-sata` (rows) | PASS | 39 |  |
| `U0-uri` (rows) | PASS | 38 |  |
| `U0-vendor` (rows) | PASS | 39 |  |
| `U1-handoff-key` (rows) | PASS | 61 | login 61.0 s / table 40/40 fields |
| `U1-sata` (rows) | PASS | 59 | login 59.0 s / table 40/40 fields |
| `U1-uri` (rows) | PASS | 61 | login 60.5 s / table 40/40 fields |
| `UB-bytes` (rows) | PASS | 20 |  |
| `UB-bytes-ra0` (rows) | PASS | 29 |  |
| `W1-sata` (rows) | PASS | 402 |  |
| `W1-uri` (rows) | PASS | 401 |  |
| `login-bios-iso-1` (runs) | PASS | 46 | login 44.9 s / table 40/40 fields |
| `login-bios-pxe-1` (runs) | PASS | 57 | login 55.5 s / table 40/40 fields |
| `login-bios-usb-1` (runs) | PASS | 51 | login 51.0 s / table 40/40 fields |
| `login-uefi-iso-1` (runs) | PASS | 57 | login 57.0 s / table 40/40 fields |
| `login-uefi-pxe-1` (runs) | PASS | 62 | login 60.5 s / table 40/40 fields |
| `login-uefi-usb-1` (runs) | PASS | 59 | login 58.5 s / table 40/40 fields |
| `loss2pct-new-1` (runs) | PASS | 98 | login 97.0 s / table 40/40 fields |
| `loss2pct-new-2` (runs) | PASS | 78 | login 78.1 s / table 40/40 fields |
| `loss2pct-new-3` (runs) | PASS | 76 | login 74.7 s / table 40/40 fields |
| `loss2pct-old-1` (runs) | PASS | 77 | login 76.4 s / table 40/40 fields |
| `loss2pct-old-2` (runs) | PASS | 82 | login 81.9 s / table 40/40 fields |
| `loss2pct-old-3` (runs) | PASS | 88 | login 87.5 s / table 40/40 fields |
| `loss8pct-new-1` (runs) | PASS | 134 | login 133.2 s / table 40/40 fields |
| `loss8pct-new-2` (runs) | FAIL | 700 | table 40/40 fields / the run script reached its expectation (met=0, stop=timeout); the stage 'login' was seen (None) |
| `loss8pct-old-1` (runs) | PASS | 137 | login 137.3 s / table 40/40 fields |
| `loss8pct-old-2` (runs) | FAIL | 152 | login 151.6 s / table 40/40 fields / the booted system's root marker (WRBOOT-ROOT-OK) was seen |
| `rd-def-1` (runs) | PASS | 74 |  |
| `rd-def-2` (runs) | PASS | 72 |  |
| `rd-oldwin-def-1` (runs) | FAIL | 174 | the cluster did not disturb the run (resent 0, session resets 3, cancels 1, stall closes 0, failed 0) |
| `rd-oldwin-def-2` (runs) | PASS | 159 |  |
| `rd-oldwin-ra0-1` (runs) | PASS | 72 |  |
| `rd-oldwin-ra0-2` (runs) | PASS | 155 |  |
| `rd-ra0-1` (runs) | PASS | 86 |  |
| `rd-ra0-2` (runs) | PASS | 79 |  |
| `rd-w128-def-1` (runs) | PASS | 146 |  |
| `rd-w128-def-2` (runs) | PASS | 153 |  |
| `rd-w128-ra0-1` (runs) | PASS | 71 |  |
| `rd-w128-ra0-2` (runs) | PASS | 69 |  |
| `rd-w256-def-1` (runs) | PASS | 156 |  |
| `rd-w256-def-2` (runs) | PASS | 173 |  |
| `rd-w256-ra0-1` (runs) | PASS | 84 |  |
| `rd-w256-ra0-2` (runs) | PASS | 83 |  |
| `winpe-W1-1` (runs) | PASS | 61 | WinPE marker at 61.0 s |
| `winpe-W1-2` (runs) | PASS | 63 | WinPE marker at 63.0 s |
| `winpe-W1-sata-marker` (runs) | PASS | 95 | WinPE marker at 95.0 s |
| `winpe-W1-uri-marker` (runs) | PASS | 70 | WinPE marker at 70.0 s |
| `winpe-W2-2` (runs) | PASS | 86 | WinPE marker at 86.0 s |
| `winpe-W2-3` (runs) | PASS | 77 | WinPE marker at 77.0 s |
| `winpe-W3-1` (runs) | PASS | 63 | WinPE marker at 63.0 s |
| `winpe-W3-2` (runs) | PASS | 81 | WinPE marker at 81.0 s |
| `winpe-W4-1` (runs) | PASS | 74 | WinPE marker at 74.0 s |
| `winpe-W4-2` (runs) | PASS | 84 | WinPE marker at 84.0 s |
| `x64-b1` (runs) | PASS | 56 | login 56.0 s / table 40/40 fields |
| `x64inst-b1` (runs) | PASS | 56 | login 55.0 s / table 40/40 fields |

| Directory | PASS | FAIL | BLOCKED | none |
|---|---|---|---|---|
| attempts | 0 | 18 | 0 | 2 |
| robust | 15 | 0 | 0 | 0 |
| rows | 16 | 0 | 0 | 0 |
| runs | 41 | 3 | 0 | 0 |
