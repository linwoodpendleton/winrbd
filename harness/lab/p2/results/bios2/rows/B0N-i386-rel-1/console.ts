# tailts start epoch=1795481192.482
8.004 iPXE initialising devices...
8.208 
8.229 
8.249 
8.270 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.290 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.311 WRRUN-STUB
11.436 Configuring (net0 52:54:00:77:12:c8)...... ok
11.457 tftp://10.77.0.10/autoexec.ipxe... ok
11.478 WRRUN-BEGIN row=B0
11.539 Waiting for link-up on net0... ok
11.560 WRRUN-NET-OK
11.580 WRRUN-SAN-START sanhook
11.866 Registered SAN device 0x81
11.887 WRRUN-SAN-OK
12.377 xbft: rBFT at 0x9e120, 233 bytes, inside the 0x80000-0xfffff window
12.398 xbft: 1 table(s) use 240 of the 2048 bytes of the area (0 refused)
12.439 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.459 rbd:   session: 49 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.480 rbd:   core stack: 1696 of 16384 bytes used
12.521 rbd:   core: connections 3 (most 3), arena 260128 bytes, bulk 2627584 bytes; modes: 3 crc, 0 secure, 0 secure failures
12.562 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
12.604 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
12.624 WRRUN-LEAVE exit
12.645 WRRUN-END
13.053 GNU GRUB  version 2.14
13.053 
13.074 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.094       Press enter to boot the selected OS, `e' to edit the commands       
20.690       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 WRBOOT-TINY start kernel=6.8.0-151-generic
20.711 
20.711 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
20.976 RBFT-HOOK table found by source scan
20.976 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
20.976 RBFT-HOOK nic: eth0 address 10.77.0.72/24
20.976 RBFT-HOOK table check (source scan):
21.221 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
21.221 RBFT PASS signature: rBFT
21.221 RBFT PASS length: 233 bytes
21.221 RBFT PASS acpi_revision: 1
21.221 RBFT PASS checksum: all 233 bytes sum to 0
21.221 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
21.221 RBFT PASS magic: WRBT
21.221 RBFT PASS version: 1
21.221 RBFT PASS header_len: 116
21.242 RBFT PASS reserved: all reserved bytes are zero
21.242 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
21.242 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (81 bytes of area)
21.242 RBFT PASS namespace: absent (as in version 1)
21.242 RBFT PASS rules: every rule of the field table holds
21.242 RBFT PASS entity: wrtest-p2-b0
21.242 RBFT PASS pool: winrbd
21.242 RBFT PASS image: wrtest-p2-b0
21.242 RBFT PASS image_id: 3fa2de52cac
21.242 RBFT PASS snapshot: absent, as expected
21.242 RBFT PASS auth: cephx
21.242 RBFT PASS msgr_mode: crc
21.242 RBFT PASS flags: key,static (0x6)
21.242 RBFT PASS flag_readonly: clear
21.242 RBFT PASS flag_key: set
21.242 RBFT PASS flag_nic_static: set
21.263 RBFT PASS flag_vlan: clear
21.263 RBFT PASS flag_fsid: clear
21.263 RBFT PASS flag_secure_required: clear
21.263 RBFT PASS key_type: aes
21.263 RBFT PASS key_len: 16
21.263 RBFT INFO key: present in the table (aes, 16 bytes), not printed
21.263 RBFT PASS mon_count: 1
21.263 RBFT PASS mon0: 10.77.0.10:3300
21.263 RBFT PASS fsid: none, as expected
21.263 RBFT PASS nic_mac: 52:54:00:77:12:c8
21.263 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
21.263 RBFT PASS nic_vlan: 0
21.263 RBFT PASS nic_mtu: 1500
21.263 RBFT PASS nic_family: 4
21.263 RBFT PASS nic_ip: 10.77.0.72
21.263 RBFT PASS nic_prefix: 24
21.284 RBFT PASS nic_gateway: zero, as expected
21.284 RBFT PASS nic_dns: zero, as expected
21.284 RBFT DUMP 0000: 72 42 46 54 e9 00 00 00 01 2c 46 45 4e 53 59 53
21.284 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
21.284 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
21.284 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
21.284 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
21.284 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
21.284 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
21.284 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
21.304 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
21.304 RBFT DUMP 0090: 2d 00 41 00 00 00 00 00 77 72 74 65 73 74 2d 70
21.304 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
21.304 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 66 61 32 64 65 35
21.304 RBFT DUMP 00c0: 32 63 61 63 00 04 00 e4 0c 0a 4d 00 0a 00 00 00
21.304 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 .. .. .. .. .. .. ..
21.304 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. ..
21.304 RBFT-RESULT PASS pass=40 fail=0 skip=0
21.304 WRBOOT-TABLE PASS
21.304 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
21.325 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
21.325 WRBOOT-EDD int13_dev81 mbr_signature=0x7d1f0002
21.325 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 fe80::5054:ff:fe77:12c8/64 
21.325 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
21.325 [    1.855919] reboot: Power down
