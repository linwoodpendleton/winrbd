# tailts start epoch=1795463264.964
8.266 iPXE initialising devices...
8.327 
8.348 
8.369 
8.389 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.430 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.451 WRRUN-STUB
11.574 Configuring (net0 52:54:00:77:12:c8)...... ok
11.615 tftp://10.77.0.10/autoexec.ipxe... ok
11.636 WRRUN-BEGIN row=B0
11.697 Waiting for link-up on net0... ok
11.718 WRRUN-NET-OK
11.864 WRRUN-SAN-START sanhook
12.088 Registered SAN device 0x81
12.109 WRRUN-SAN-OK
12.150 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.170 rbd:   session: 37 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.232 rbd:   core: connections 2 (most 2), arena 263392 bytes, bulk 2627584 bytes; modes: 2 crc, 0 secure, 0 secure failures
12.314 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
12.355 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
12.376 WRRUN-LEAVE exit
12.397 WRRUN-END
12.992 GNU GRUB  version 2.14
12.992 
13.012 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.012       Press enter to boot the selected OS, `e' to edit the commands       
17.097       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 WRBOOT-TINY start kernel=6.8.0-151-generic
17.118 
17.118 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
17.383 RBFT-HOOK table found by source scan
17.383 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
17.383 RBFT-HOOK nic: eth0 address 10.77.0.72/24
17.383 RBFT-HOOK table check (source scan):
17.629 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
17.629 RBFT PASS signature: rBFT
17.629 RBFT PASS length: 234 bytes
17.629 RBFT PASS acpi_revision: 1
17.649 RBFT PASS checksum: all 234 bytes sum to 0
17.649 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
17.649 RBFT PASS magic: WRBT
17.649 RBFT PASS version: 1
17.649 RBFT PASS header_len: 116
17.649 RBFT PASS reserved: all reserved bytes are zero
17.649 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.649 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.649 RBFT PASS namespace: absent (as in version 1)
17.649 RBFT PASS rules: every rule of the field table holds
17.649 RBFT PASS entity: wrtest-p2-b0
17.649 RBFT PASS pool: winrbd
17.649 RBFT PASS image: wrtest-p2-b0
17.649 RBFT PASS image_id: 3941520e0799
17.649 RBFT PASS snapshot: absent, as expected
17.670 RBFT PASS auth: cephx
17.670 RBFT PASS msgr_mode: crc
17.670 RBFT PASS flags: key,static (0x6)
17.670 RBFT PASS flag_readonly: clear
17.670 RBFT PASS flag_key: set
17.670 RBFT PASS flag_nic_static: set
17.670 RBFT PASS flag_vlan: clear
17.670 RBFT PASS flag_fsid: clear
17.670 RBFT PASS flag_secure_required: clear
17.670 RBFT PASS key_type: aes
17.670 RBFT PASS key_len: 16
17.670 RBFT INFO key: present in the table (aes, 16 bytes), not printed
17.670 RBFT PASS mon_count: 1
17.670 RBFT PASS mon0: 10.77.0.10:3300
17.670 RBFT PASS fsid: none, as expected
17.670 RBFT PASS nic_mac: 52:54:00:77:12:c8
17.670 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
17.670 RBFT PASS nic_vlan: 0
17.670 RBFT PASS nic_mtu: 1500
17.670 RBFT PASS nic_family: 4
17.670 RBFT PASS nic_ip: 10.77.0.72
17.670 RBFT PASS nic_prefix: 24
17.691 RBFT PASS nic_gateway: zero, as expected
17.691 RBFT PASS nic_dns: zero, as expected
17.691 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ed 46 45 4e 53 59 53
17.691 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
17.691 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
17.691 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
17.691 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
17.691 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
17.691 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.691 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.691 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
17.691 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
17.711 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
17.711 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 39 34 31 35 32 30
17.711 RBFT DUMP 00c0: 65 30 37 39 39 00 04 00 e4 0c 0a 4d 00 0a 00 00
17.711 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
17.711 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
17.711 RBFT-RESULT PASS pass=40 fail=0 skip=0
17.797 WRBOOT-TABLE PASS
17.797 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
17.818 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
17.818 WRBOOT-EDD int13_dev81 mbr_signature=0x7d1f0002
17.818 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 fe80::5054:ff:fe77:12c8/64 
17.818 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
17.838 [    2.230264] reboot: Power down
