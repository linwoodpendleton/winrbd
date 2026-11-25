| Row | Verdict | Fault (begin / end after guest start) | Workload s | cancels | reopens | stall closes | resent | session resets | New connections after the fault began | Reader: errors / slowest read | First FAIL |
|---|---|---|---|---|---|---|---|---|---|---|---|
| B1-boot-ctl | PASS | none - / - | 8.6 | - | - | - | - | - | 0 | - |  |
| B1-boot-idle | PASS | pause +13.5 s / +74.0 s | 69.8 | - | - | - | - | - | 2 mon, 6 osd | - |  |
| B1-boot-link | PASS | link-down +13.1 s / +53.6 s | 47.5 | - | - | - | - | - | 3 mon, 5 osd | - |  |
| B1-boot-mon | PASS | mon-kill +13.3 s / +37.3 s | 7.8 | - | - | - | - | - | 16 mon, 0 osd | - |  |
| B1-boot-mon-osd | PASS | mon-osd +21.0 s / +64.8 s | 15.9 | - | - | - | - | - | 16 mon, 0 osd | - |  |
| B1-boot-mon-short | PASS | mon-kill +13.1 s / +18.3 s | 6.3 | - | - | - | - | - | 4 mon, 3 osd | - |  |
| B1-boot-osd-esp | PASS | osd-kill +11.2 s / +55.7 s | 7.7 | - | - | - | - | - | 2 mon, 4 osd | - |  |
| B1-boot-osd-kernel | PASS | osd-kill +16.1 s / +67.9 s | 20.2 | - | - | - | - | - | 2 mon, 2 osd | - |  |
| B1-boot-outage | PASS | outage +14.0 s / +346.9 s | - | - | - | - | - | - | 0 mon, 16 osd | - |  |
| B1-boot-pause | PASS | pause +13.3 s / +73.8 s | 67.1 | - | - | - | - | - | 4 mon, 3 osd | - |  |
| B1-boot-stall20 | PASS | stall +13.9 s / +36.8 s | 28.6 | - | - | - | - | - | 2 mon, 5 osd | - |  |
| B1-neg-image | PASS | none - / - | - | - | - | - | - | - | 0 | - |  |
| B1-neg-key | FAIL | none - / - | - | - | - | - | - | - | 0 | - | the errno is the right one: EPROTO (0x43766001), want EACCES |
| B1-neg-mon | PASS | none - / - | - | - | - | - | - | - | 0 | - |  |
| B1-neg-pool | PASS | none - / - | - | - | - | - | - | - | 0 | - |  |
| B1-reader-ctl | PASS | none - / - | 11.5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0.4 s |  |
| B1-reader-idle | PASS | pause +13.3 s / +73.6 s | 80.3 | 0 | 0 | 0 | 7 | 3 | 1 mon, 3 osd | 0 / 2.3 s |  |
| B1-reader-link | PASS | link-down +13.4 s / +53.6 s | 56.9 | 3 | 0 | 1 | 1 | 7 | 1 mon, 3 osd | 0 / 40.5 s |  |
| B1-reader-mon | PASS | mon-kill +13.0 s / +26.0 s | 12.8 | 0 | 0 | 0 | 0 | 0 | 4 mon, 1 osd | 0 / 0.4 s |  |
| B1-reader-mon-osd | PASS | mon-osd +13.0 s / +54.2 s | 41.7 | 1 | 0 | 0 | 1 | 6 | 6 mon, 5 osd | 0 / 27.7 s |  |
| B1-reader-mon-short | PASS | mon-kill +12.9 s / +19.3 s | 13.4 | 0 | 0 | 0 | 0 | 0 | 4 mon, 0 osd | 0 / 0.7 s |  |
| B1-reader-osd-long | PASS | osd-kill +13.0 s / +25.8 s | 12.7 | 0 | 0 | 0 | 0 | 1 | 0 | 0 / 1.5 s |  |
| B1-reader-osd-short | PASS | osd-kill +12.8 s / +25.3 s | 12.4 | 0 | 0 | 0 | 0 | 1 | 0 mon, 1 osd | 0 / 1.9 s |  |
| B1-reader-outage | PASS | outage +12.4 s / +435.4 s | 437.4 | 28 | 0 | 13 | 1 | 47 | 0 mon, 16 osd | 2 / 94.3 s |  |
| B1-reader-pause | PASS | pause +12.8 s / +72.9 s | 73.6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0.4 s |  |
| B1-reader-stall20 | PASS | stall +23.4 s / +46.5 s | 34.1 | 1 | 0 | 0 | 1 | 2 | 0 mon, 2 osd | 0 / 20.8 s |  |
| B1-reader-stall40 | PASS | stall +13.2 s / +55.5 s | 54.9 | 2 | 0 | 0 | 1 | 4 | 0 mon, 5 osd | 0 / 42.4 s |  |
| U1-boot-ctl | PASS | none - / - | 8.0 | - | - | - | - | - | 0 | - |  |
| U1-boot-idle | PASS | pause +14.7 s / +75.2 s | 69.4 | - | - | - | - | - | 3 mon, 6 osd | - |  |
| U1-boot-link | PASS | link-down +13.8 s / +54.3 s | 51.7 | - | - | - | - | - | 2 mon, 4 osd | - |  |
| U1-boot-mon | PASS | mon-kill +16.9 s / +41.1 s | 9.4 | - | - | - | - | - | 16 mon, 0 osd | - |  |
| U1-boot-mon-osd | PASS | mon-osd +16.6 s / +60.6 s | 35.1 | - | - | - | - | - | 8 mon, 7 osd | - |  |
| U1-boot-mon-short | PASS | mon-kill +17.8 s / +23.7 s | 10.8 | - | - | - | - | - | 5 mon, 3 osd | - |  |
| U1-boot-osd-esp | PASS | osd-kill +13.5 s / +60.9 s | 12.2 | - | - | - | - | - | 2 mon, 2 osd | - |  |
| U1-boot-osd-kernel | PASS | osd-kill +16.5 s / +59.3 s | 10.8 | - | - | - | - | - | 1 mon, 2 osd | - |  |
| U1-boot-outage | PASS | outage +14.1 s / +347.2 s | - | - | - | - | - | - | 0 mon, 16 osd | - |  |
| U1-boot-pause | PASS | pause +16.4 s / +76.9 s | 69.4 | - | - | - | - | - | 1 mon, 3 osd | - |  |
| U1-boot-stall20 | PASS | stall +13.9 s / +35.8 s | 27.7 | - | - | - | - | - | 2 mon, 5 osd | - |  |
| U1-bytes-ctl | PASS | none - / - | 15.4 | 0 | 0 | 0 | 0 | 0 | 0 | - |  |
| U1-bytes-idle | PASS | pause +19.6 s / +79.8 s | 114.6 | 0 | 0 | 0 | 8 | 3 | 1 mon, 4 osd | - |  |
| U1-bytes-link | PASS | link-down +12.5 s / +52.5 s | 57.3 | 3 | 0 | 1 | 0 | 10 | 1 mon, 2 osd | - |  |
| U1-bytes-mon | PASS | mon-kill +12.2 s / +23.0 s | 10.6 | 0 | 0 | 0 | 0 | 0 | 4 mon, 0 osd | - |  |
| U1-bytes-mon-osd | PASS | mon-osd +12.2 s / +49.9 s | 38.1 | 1 | 0 | 0 | 0 | 5 | 6 mon, 4 osd | - |  |
| U1-bytes-mon-short | PASS | mon-kill +13.5 s / +19.5 s | 14.9 | 0 | 0 | 0 | 0 | 0 | 4 mon, 0 osd | - |  |
| U1-bytes-osd-long | PASS | osd-kill +12.1 s / +25.6 s | 13.6 | 0 | 0 | 0 | 7 | 1 | 0 | - |  |
| U1-bytes-osd-short | PASS | osd-kill +11.6 s / +24.0 s | 12.5 | 0 | 0 | 0 | 0 | 1 | 0 | - |  |
| U1-bytes-outage | PASS | outage +12.4 s / +168.5 s | 156.8 | 11 | 0 | 4 | 0 | 17 | 0 mon, 16 osd | - |  |
| U1-bytes-pause | PASS | pause +12.1 s / +72.2 s | 72.4 | 0 | 0 | 0 | 0 | 0 | 0 | - |  |
| U1-bytes-stall20 | PASS | stall +11.6 s / +33.4 s | 33.6 | 1 | 0 | 0 | 0 | 2 | 0 mon, 2 osd | - |  |
| U1-bytes-stall40 | PASS | stall +12.0 s / +54.6 s | 55.9 | 3 | 0 | 1 | 0 | 4 | 0 mon, 6 osd | - |  |
| U1-neg-image | PASS | none - / - | - | - | - | - | - | - | 0 | - |  |
| U1-neg-key | FAIL | none - / - | - | - | - | - | - | - | 0 | - | the errno is the right one: EPROTO (0x43766098), want EACCES |
| U1-neg-mon | PASS | none - / - | - | - | - | - | - | - | 0 | - |  |
| U1-neg-pool | PASS | none - / - | - | - | - | - | - | - | 0 | - |  |

| Family and workload | PASS | FAIL | BLOCKED |
|---|---|---|---|
| B1-boot | 11 | 0 | 0 |
| B1-neg | 3 | 1 | 0 |
| B1-reader | 12 | 0 | 0 |
| U1-boot | 11 | 0 | 0 |
| U1-bytes | 12 | 0 | 0 |
| U1-neg | 3 | 1 | 0 |
