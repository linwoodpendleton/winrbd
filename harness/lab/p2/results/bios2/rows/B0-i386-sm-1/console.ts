# tailts start epoch=1795480907.909
7.902 iPXE initialising devices...
7.922 
7.943 
7.964 
7.984 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.005 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.025 WRRUN-STUB
11.117 Configuring (net0 52:54:00:77:12:c8)...... ok
11.159 tftp://10.77.0.10/autoexec.ipxe... ok
11.179 WRRUN-BEGIN row=B0
11.241 Waiting for link-up on net0... ok
11.261 WRRUN-NET-OK
11.282 WRRUN-SAN-START sanhook
11.323 rbd: stack high-water 2120 of 4096 bytes (1976 left)
11.343 rbd: core stack high-water 512 of 16384 bytes
11.385 rbd: stack high-water 2120 of 4096 bytes (1976 left)
11.406 rbd: core stack high-water 788 of 16384 bytes
11.426 rbd: stack high-water 2120 of 4096 bytes (1976 left)
11.447 rbd: core stack high-water 1304 of 16384 bytes
11.488 rbd: stack high-water 2120 of 4096 bytes (1976 left)
11.509 rbd: core stack high-water 1588 of 16384 bytes
11.816 Registered SAN device 0x81
11.837 WRRUN-SAN-OK
12.328 xbft: rBFT at 0x9a880, 233 bytes, inside the 0x80000-0xfffff window
12.369 xbft: 1 table(s) use 240 of the 2048 bytes of the area (0 refused)
12.389 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.410 rbd:   session: 39 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.431 rbd:   core stack: 1696 of 16384 bytes used
12.492 rbd:   core: connections 3 (most 3), arena 260128 bytes, bulk 2627584 bytes; modes: 3 crc, 0 secure, 0 secure failures
12.533 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
12.575 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
12.595 rbd: stack high-water 2120 of 4096 bytes (1976 left)
12.616 WRRUN-LEAVE exit
12.637 WRRUN-END
12.740 rbd: net0: an RBD drive is hooked and iPXE is exiting over a UNDI network device: the PXE ROM stops its network stack when iPXE returns, and reads of the drive will then stall (boot with sanboot, or use ipxe.pxe with a native driver)
16.282 GNU GRUB  version 2.14
16.282 
16.302 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
16.302       Press enter to boot the selected OS, `e' to edit the commands       
50.485       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
53.501 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
80.617 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
83.644 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
110.779 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
113.791 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
130.583 WRBOOT-TINY start kernel=6.8.0-151-generic
130.625 
130.625 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
130.890 RBFT-HOOK table found by source scan
130.890 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
130.890 RBFT-HOOK nic: eth0 address 10.77.0.72/24
130.890 RBFT-HOOK table check (source scan):
131.135 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
131.135 RBFT PASS signature: rBFT
131.135 RBFT PASS length: 233 bytes
131.156 RBFT PASS acpi_revision: 1
131.156 RBFT PASS checksum: all 233 bytes sum to 0
131.156 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
131.156 RBFT PASS magic: WRBT
131.156 RBFT PASS version: 1
131.156 RBFT PASS header_len: 116
131.156 RBFT PASS reserved: all reserved bytes are zero
131.156 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
131.156 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (81 bytes of area)
131.156 RBFT PASS namespace: absent (as in version 1)
131.156 RBFT PASS rules: every rule of the field table holds
131.156 RBFT PASS entity: wrtest-p2-b0
131.156 RBFT PASS pool: winrbd
131.156 RBFT PASS image: wrtest-p2-b0
131.156 RBFT PASS image_id: 3fa2de52cac
131.156 RBFT PASS snapshot: absent, as expected
131.156 RBFT PASS auth: cephx
131.156 RBFT PASS msgr_mode: crc
131.156 RBFT PASS flags: key,static (0x6)
131.156 RBFT PASS flag_readonly: clear
131.177 RBFT PASS flag_key: set
131.177 RBFT PASS flag_nic_static: set
131.177 RBFT PASS flag_vlan: clear
131.177 RBFT PASS flag_fsid: clear
131.177 RBFT PASS flag_secure_required: clear
131.177 RBFT PASS key_type: aes
131.177 RBFT PASS key_len: 16
131.177 RBFT INFO key: present in the table (aes, 16 bytes), not printed
131.177 RBFT PASS mon_count: 1
131.177 RBFT PASS mon0: 10.77.0.10:3300
131.177 RBFT PASS fsid: none, as expected
131.177 RBFT PASS nic_mac: 52:54:00:77:12:c8
131.177 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
131.177 RBFT PASS nic_vlan: 0
131.177 RBFT PASS nic_mtu: 1500
131.177 RBFT PASS nic_family: 4
131.177 RBFT PASS nic_ip: 10.77.0.72
131.177 RBFT PASS nic_prefix: 24
131.177 RBFT PASS nic_gateway: zero, as expected
131.177 RBFT PASS nic_dns: zero, as expected
131.177 RBFT DUMP 0000: 72 42 46 54 e9 00 00 00 01 2c 46 45 4e 53 59 53
131.177 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
131.197 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
131.197 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
131.197 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
131.197 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
131.197 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
131.197 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
131.197 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
131.197 RBFT DUMP 0090: 2d 00 41 00 00 00 00 00 77 72 74 65 73 74 2d 70
131.197 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
131.197 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 66 61 32 64 65 35
131.197 RBFT DUMP 00c0: 32 63 61 63 00 04 00 e4 0c 0a 4d 00 0a 00 00 00
131.197 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 .. .. .. .. .. .. ..
131.218 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. ..
131.218 RBFT-RESULT PASS pass=40 fail=0 skip=0
131.218 WRBOOT-TABLE PASS
131.218 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
131.218 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
131.218 WRBOOT-EDD int13_dev81 mbr_signature=-
131.218 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 
131.239 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
131.239 [    1.926675] reboot: Power down
