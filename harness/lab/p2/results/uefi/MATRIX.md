<!-- SPDX-License-Identifier: MIT -->
# The UEFI rows, one line per evidence directory

Made by `tools/summarize.py rows` from the verdicts and stamps of each directory (seconds are since the start of the run script, within a second or two of the start of the guest). A dash means the row did not get there (or the stage does not exist in it). See README.md for what each row is and for the repeats (U1-vendor-rN, -ra0-rN, -abdef/-abra0-rN interleaved, -ldef/-lra0-rN under a build load, -r1NN/-r2NN debug builds, HTTP-rN control).

| Row | Verdict | iPXE s | SAN ok s | grub s | table s | root s | login s | Notes |
|---|---|---|---|---|---|---|---|---|
| HTTP-r1 | PASS | 11 | - | 11.5 | 17.5 | - | - |  |
| HTTP-r10 | PASS | 11 | - | 12.0 | 18.0 | - | - |  |
| HTTP-r11 | PASS | 11 | - | 12.0 | 18.0 | - | - |  |
| HTTP-r12 | PASS | 11 | - | 11.5 | 17.5 | - | - |  |
| HTTP-r13 | PASS | 11 | - | 11.5 | 17.5 | - | - |  |
| HTTP-r14 | PASS | 11 | - | 11.5 | 18.0 | - | - |  |
| HTTP-r2 | PASS | 11 | - | 12.0 | 18.0 | - | - |  |
| HTTP-r3 | PASS | 11 | - | 12.0 | 18.5 | - | - |  |
| HTTP-r4 | PASS | 11 | - | 12.5 | 18.5 | - | - |  |
| HTTP-r5 | PASS | 11 | - | 12.5 | 18.0 | - | - |  |
| HTTP-r6 | PASS | 10 | - | 11.5 | 17.5 | - | - |  |
| HTTP-r7 | PASS | 11 | - | 12.0 | 18.0 | - | - |  |
| HTTP-r8 | PASS | 11 | - | 12.0 | 18.5 | - | - |  |
| HTTP-r9 | PASS | 11 | - | 12.0 | 18.0 | - | - |  |
| N-nokey | PASS | 66 | failed@68 | - | - | - | - | errno is EINVAL: EINVAL |
| N-nomon | PASS | 12 | failed@28 | - | - | - | - | errno is ETIMEDOUT/ENETUNREACH: ENETUNREACH |
| N-password | PASS | 12 | failed@13 | - | - | - | - | errno is EINVAL: EINVAL |
| N-wrongimage | PASS | 12 | failed@12 | - | - | - | - | errno is ENOENT: ENOENT |
| N-wrongkey | FAIL | 19 | failed@35 | - | - | - | - | console line /rbd: .*failed: .*\(WR_E_AUTH_[A-Z_]+\)/: not in the log |
| N-wrongpool | PASS | 12 | failed@13 | - | - | - | - | errno is ENOENT: ENOENT |
| U0-sata | PASS | 12 | 13 | - | - | - | - | device path flavour sata: 10 map entries carry the node, e.g. PciRoot(0x0)/Pci(0 |
| U0-uri | FAIL | 13 | failed@14 | - | - | - | - | reached the UEFI shell: RESULT met=0 stop=guest-exited |
| U0-vendor | PASS | 12 | 13 | - | - | - | - | device path flavour vendor: 10 map entries carry the node, e.g. PciRoot(0x0)/Pci |
| U1-handoff-key | PASS | 11 | - | 13.5 | 20.6 | 53.7 | 59.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-sata | PASS | 11 | - | 13.0 | 22.1 | 70.3 | 75.8 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-uri | FAIL | 12 | failed@12 | - | - | - | - | run met its expectation: RESULT met=0 stop=guest-exited |
| U1-vendor | PASS | 11 | - | 12.5 | 20.0 | 54.1 | 59.6 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r1 | PASS | 11 | - | 13.5 | 20.6 | 54.7 | 60.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r10 | PASS | 12 | - | 15.6 | 24.1 | 58.3 | 64.8 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r2 | PASS | 11 | - | 13.0 | 20.1 | 54.2 | 59.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r3 | PASS | 11 | - | 13.0 | 20.1 | 53.7 | 59.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r4 | PASS | 12 | - | 14.0 | 21.6 | 55.2 | 60.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r5 | PASS | 11 | - | 13.5 | 21.6 | 54.7 | 60.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r6 | PASS | 11 | - | 15.0 | 24.1 | 57.7 | 63.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r7 | PASS | 11 | - | 15.0 | 22.6 | 55.7 | 61.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r8 | PASS | 12 | - | 13.5 | 21.6 | 54.7 | 60.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abdef-r9 | PASS | 11 | - | 15.5 | 24.1 | 58.2 | 64.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r1 | PASS | 11 | - | 13.5 | 25.1 | 58.2 | 63.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r10 | PASS | 13 | - | 16.1 | 29.1 | 63.3 | 69.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r2 | PASS | 12 | - | 15.1 | 26.6 | 60.2 | 66.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r3 | PASS | 12 | - | 14.5 | 24.6 | 59.7 | 65.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r4 | PASS | 11 | - | 13.0 | 23.6 | 57.2 | 63.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r5 | PASS | 11 | - | 13.0 | 22.1 | 55.2 | 61.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r6 | PASS | 11 | - | 13.0 | 22.6 | 56.2 | 61.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r7 | PASS | 11 | - | 12.5 | 22.1 | 55.2 | 61.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r8 | PASS | 11 | - | 13.0 | 24.1 | 57.2 | 62.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-abra0-r9 | PASS | 13 | - | 15.1 | 29.1 | 63.3 | 68.8 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r1 | PASS | 12 | - | 15.1 | 23.6 | 57.8 | 63.9 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r2 | PASS | 12 | - | 16.6 | 24.1 | 59.3 | 64.8 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r3 | PASS | 14 | - | 17.6 | 26.1 | 60.3 | 65.8 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r4 | PASS | 13 | - | 16.0 | 25.7 | 59.3 | 65.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r5 | PASS | 12 | - | 14.0 | 22.1 | 55.7 | 61.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r6 | PASS | 12 | - | 15.6 | 23.6 | 57.2 | 63.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ldef-r7 | PASS | 12 | - | 13.5 | 21.6 | 55.2 | 60.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r1 | PASS | 13 | - | 15.1 | 27.1 | 61.3 | 67.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r2 | PASS | 12 | - | 15.1 | 29.2 | 64.4 | 69.9 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r3 | PASS | 12 | - | 14.0 | 24.1 | 57.7 | 63.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r4 | PASS | 12 | - | 14.5 | 26.1 | 59.7 | 65.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r5 | PASS | 12 | - | 14.0 | 33.1 | 66.7 | 72.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r6 | PASS | 12 | - | 14.5 | 31.1 | 64.7 | 70.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-lra0-r7 | PASS | 12 | - | 14.0 | 25.1 | 58.7 | 64.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r1 | PASS | 12 | - | 14.0 | 22.5 | 57.1 | 62.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r10 | PASS | 17 | - | 21.6 | 33.7 | 71.5 | 77.0 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r101 | PASS | 15 | - | 19.1 | 29.2 | 66.4 | 71.9 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r102 | FAIL | 16 | - | 18.6 | - | - | - | run met its expectation: RESULT met=0 stop=fail-marker |
| U1-vendor-r103 | FAIL | 14 | - | 18.1 | - | - | - | run met its expectation: RESULT met=0 stop=fail-marker |
| U1-vendor-r104 | FAIL | 15 | - | 20.1 | - | - | - | run met its expectation: RESULT met=0 stop=fail-marker |
| U1-vendor-r105 | PASS | 14 | - | 17.1 | 41.2 | 79.0 | 84.0 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r106 | PASS | 15 | - | 19.1 | 28.1 | 63.3 | 68.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r11 | FAIL | 27 | - | 37.3 | - | - | - | run met its expectation: RESULT met=0 stop=guest-exited |
| U1-vendor-r12 | FAIL | 35 | - | 43.9 | - | - | - | run met its expectation: RESULT met=0 stop=guest-exited |
| U1-vendor-r13 | PASS | 16 | - | 21.1 | 31.2 | 70.4 | 76.0 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r14 | FAIL | 14 | - | 19.6 | - | - | - | run met its expectation: RESULT met=0 stop=fail-marker |
| U1-vendor-r2 | PASS | 12 | - | 15.0 | 23.5 | 60.2 | 66.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r201 | PASS | 12 | - | 15.6 | 49.2 | 84.0 | 89.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r202 | FAIL | 11 | - | 17.6 | - | - | - | run met its expectation: RESULT met=0 stop=fail-marker |
| U1-vendor-r3 | PASS | 13 | - | 16.5 | 23.6 | 63.2 | 69.3 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r4 | FAIL | 17 | - | 20.6 | - | - | - | run met its expectation: RESULT met=0 stop=guest-exited |
| U1-vendor-r5 | PASS | 12 | - | 14.0 | 21.0 | 55.6 | 61.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r6 | PASS | 12 | - | 14.0 | 22.5 | 59.7 | 65.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r7 | PASS | 12 | - | 15.5 | 23.5 | 61.7 | 67.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r8 | PASS | 13 | - | 16.0 | 43.6 | 109.2 | 112.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-r9 | PASS | 21 | - | 25.7 | 39.3 | 77.1 | 83.1 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r1 | PASS | 11 | - | 12.0 | 21.1 | 54.2 | 60.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r10 | PASS | 11 | - | 12.5 | 21.1 | 56.2 | 61.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r2 | PASS | 11 | - | 12.5 | 21.6 | 55.2 | 60.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r3 | PASS | 11 | - | 12.5 | 21.6 | 54.2 | 60.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r4 | PASS | 11 | - | 12.5 | 20.6 | 53.7 | 59.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r5 | PASS | 11 | - | 12.5 | 21.6 | 54.2 | 60.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r6 | PASS | 11 | - | 13.5 | 22.6 | 56.2 | 61.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r7 | PASS | 12 | - | 13.5 | 22.6 | 55.7 | 61.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r8 | PASS | 11 | - | 13.0 | 21.6 | 54.7 | 60.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U1-vendor-ra0-r9 | PASS | 10 | - | 12.5 | 20.6 | 54.2 | 59.7 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U2-usb | PASS | 8 | - | 10.4 | 20.4 | 54.0 | 59.5 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| U3-iso | PASS | 7 | - | 9.0 | 16.0 | 49.2 | 55.2 | table: RBFT-RESULT PASS: RBFT-RESULT PASS pass=40 fail=0 skip=0; table: RBFT-RESULT counts agree with the lines: pass=40 fail=0 skip=0 |
| UB-bytes | PASS | 12 | 13 | - | - | - | - | every file: iPXE digest == build list == rbd export: 18 of 18 files |
| UB-bytes-ra0 | PASS | 27 | 28 | - | - | - | - | every file: iPXE digest == build list == rbd export: 18 of 18 files |
| W1-sata | FAIL | 12 | - | - | - | - | - | S4 the WinPE desktop is on the screen (heuristic, see the screenshots): no screenshot has the WinPE colour in  |
| W1-sata-a2 | FAIL | 36 | - | - | - | - | - | S4 the WinPE desktop is on the screen (heuristic, see the screenshots): no screenshot has the WinPE colour in  |
| W1-uri | FAIL | 11 | failed@13 | - | - | - | - | S1 iPXE registered the SAN device and booted from it: no 'Registered SAN device' and 'Booting from SAN device' |
| W1-vendor | PASS | 14 | - | - | - | - | - |  |
| W1-vendor-a2 | PASS | 12 | - | - | - | - | - |  |
| W2-vendor | PASS | 9 | - | - | - | - | - |  |

| Family (runs of the same row; [binary] when it is not ipxe.efi) | Runs | PASS | FAIL | BLOCKED |
|---|---|---|---|---|
| HTTP | 14 | 14 | 0 | 0 |
| N-nokey | 1 | 1 | 0 | 0 |
| N-nomon | 1 | 1 | 0 | 0 |
| N-password | 1 | 1 | 0 | 0 |
| N-wrongimage | 1 | 1 | 0 | 0 |
| N-wrongkey | 1 | 0 | 1 | 0 |
| N-wrongpool | 1 | 1 | 0 | 0 |
| U0-sata | 1 | 1 | 0 | 0 |
| U0-uri | 1 | 0 | 1 | 0 |
| U0-vendor | 1 | 1 | 0 | 0 |
| U1-handoff-key | 1 | 1 | 0 | 0 |
| U1-sata | 1 | 1 | 0 | 0 |
| U1-uri | 1 | 0 | 1 | 0 |
| U1-vendor | 15 | 11 | 4 | 0 |
| U1-vendor [ipxe-dbg.efi] | 6 | 3 | 3 | 0 |
| U1-vendor [ipxe-dbg2.efi] | 2 | 1 | 1 | 0 |
| U1-vendor-abdef | 10 | 10 | 0 | 0 |
| U1-vendor-abra0 | 10 | 10 | 0 | 0 |
| U1-vendor-ldef | 7 | 7 | 0 | 0 |
| U1-vendor-lra0 | 7 | 7 | 0 | 0 |
| U1-vendor-ra0 | 10 | 10 | 0 | 0 |
| U2-usb | 1 | 1 | 0 | 0 |
| U3-iso | 1 | 1 | 0 | 0 |
| UB-bytes | 1 | 1 | 0 | 0 |
| UB-bytes-ra0 | 1 | 1 | 0 | 0 |
| W1-sata | 1 | 0 | 1 | 0 |
| W1-sata-a2 | 1 | 0 | 1 | 0 |
| W1-uri | 1 | 0 | 1 | 0 |
| W1-vendor | 1 | 1 | 0 | 0 |
| W1-vendor-a2 | 1 | 1 | 0 | 0 |
| W2-vendor | 1 | 1 | 0 | 0 |
