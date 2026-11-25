# tailts start epoch=1795481050.883
7.970 iPXE initialising devices...
7.990 
8.011 
8.031 
8.052 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.094 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.115 WRRUN-STUB
11.241 Configuring (net0 52:54:00:77:12:c8)...... ok
11.282 tftp://10.77.0.10/autoexec.ipxe... ok
11.302 WRRUN-BEGIN row=B0
11.364 Waiting for link-up on net0... ok
11.384 WRRUN-NET-OK
11.404 WRRUN-SAN-START sanhook
11.670 Registered SAN device 0x81
11.691 WRRUN-SAN-OK
12.160 xbft: rBFT at 0x9a840, 233 bytes, inside the 0x80000-0xfffff window
12.201 xbft: 1 table(s) use 240 of the 2048 bytes of the area (0 refused)
12.222 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.263 rbd:   session: 33 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.304 rbd:   core: connections 3 (most 3), arena 263392 bytes, bulk 2627584 bytes; modes: 3 crc, 0 secure, 0 secure failures
12.365 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
12.426 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
12.426 WRRUN-LEAVE exit
12.447 WRRUN-END
12.549 rbd: net0: an RBD drive is hooked and iPXE is exiting over a UNDI network device: the PXE ROM stops its network stack when iPXE returns, and reads of the drive will then stall (boot with sanboot, or use ipxe.pxe with a native driver)
15.998 GNU GRUB  version 2.14
15.998 
16.019 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
16.019       Press enter to boot the selected OS, `e' to edit the commands       
50.086       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
53.090 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
80.239 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
83.261 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
110.377 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
113.401 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
130.144 WRBOOT-TINY start kernel=6.8.0-151-generic
130.165 
130.165 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
130.410 RBFT-HOOK table found by source scan
130.410 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
130.430 RBFT-HOOK nic: eth0 address 10.77.0.72/24
130.430 RBFT-HOOK table check (source scan):
130.675 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
130.675 RBFT PASS signature: rBFT
130.675 RBFT PASS length: 233 bytes
130.675 RBFT PASS acpi_revision: 1
130.675 RBFT PASS checksum: all 233 bytes sum to 0
130.675 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
130.675 RBFT PASS magic: WRBT
130.675 RBFT PASS version: 1
130.675 RBFT PASS header_len: 116
130.675 RBFT PASS reserved: all reserved bytes are zero
130.675 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
130.675 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (81 bytes of area)
130.675 RBFT PASS namespace: absent (as in version 1)
130.675 RBFT PASS rules: every rule of the field table holds
130.696 RBFT PASS entity: wrtest-p2-b0
130.696 RBFT PASS pool: winrbd
130.696 RBFT PASS image: wrtest-p2-b0
130.696 RBFT PASS image_id: 3fa2de52cac
130.696 RBFT PASS snapshot: absent, as expected
130.696 RBFT PASS auth: cephx
130.696 RBFT PASS msgr_mode: crc
130.696 RBFT PASS flags: key,static (0x6)
130.696 RBFT PASS flag_readonly: clear
130.696 RBFT PASS flag_key: set
130.696 RBFT PASS flag_nic_static: set
130.696 RBFT PASS flag_vlan: clear
130.696 RBFT PASS flag_fsid: clear
130.696 RBFT PASS flag_secure_required: clear
130.696 RBFT PASS key_type: aes
130.696 RBFT PASS key_len: 16
130.696 RBFT INFO key: present in the table (aes, 16 bytes), not printed
130.696 RBFT PASS mon_count: 1
130.696 RBFT PASS mon0: 10.77.0.10:3300
130.696 RBFT PASS fsid: none, as expected
130.696 RBFT PASS nic_mac: 52:54:00:77:12:c8
130.696 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
130.696 RBFT PASS nic_vlan: 0
130.696 RBFT PASS nic_mtu: 1500
130.696 RBFT PASS nic_family: 4
130.717 RBFT PASS nic_ip: 10.77.0.72
130.717 RBFT PASS nic_prefix: 24
130.717 RBFT PASS nic_gateway: zero, as expected
130.717 RBFT PASS nic_dns: zero, as expected
130.717 RBFT DUMP 0000: 72 42 46 54 e9 00 00 00 01 2c 46 45 4e 53 59 53
130.717 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
130.717 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
130.717 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
130.717 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
130.717 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
130.717 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
130.717 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
130.737 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
130.737 RBFT DUMP 0090: 2d 00 41 00 00 00 00 00 77 72 74 65 73 74 2d 70
130.737 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
130.737 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 66 61 32 64 65 35
130.737 RBFT DUMP 00c0: 32 63 61 63 00 04 00 e4 0c 0a 4d 00 0a 00 00 00
130.737 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 .. .. .. .. .. .. ..
130.737 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. ..
130.737 RBFT-RESULT PASS pass=40 fail=0 skip=0
130.737 WRBOOT-TABLE PASS
130.737 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
130.758 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
130.758 WRBOOT-EDD int13_dev81 mbr_signature=-
130.758 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 
130.758 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
130.778 [    1.823794] reboot: Power down
