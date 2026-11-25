# tailts start epoch=1795464571.502
8.169 iPXE initialising devices...
8.374 
8.394 
8.394 
8.436 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.457 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.477 WRRUN-STUB
11.592 Configuring (net0 52:54:00:77:12:c8)...... ok
11.613 tftp://10.77.0.10/autoexec.ipxe... ok
11.634 WRRUN-BEGIN row=B0
11.738 Waiting for link-up on net0... ok
11.758 WRRUN-NET-OK
11.779 WRRUN-SAN-START sanhook
11.984 Registered SAN device 0x81
12.004 WRRUN-SAN-OK
12.046 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.089 rbd:   session: 34 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.110 rbd:   core stack: 1696 of 16384 bytes used
12.172 rbd:   core: connections 2 (most 2), arena 260128 bytes, bulk 2627584 bytes; modes: 2 crc, 0 secure, 0 secure failures
12.213 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
12.275 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
12.295 WRRUN-LEAVE exit
12.295 WRRUN-END
12.786 GNU GRUB  version 2.14
12.786 
12.807 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
12.807       Press enter to boot the selected OS, `e' to edit the commands       
20.152       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 WRBOOT-TINY start kernel=6.8.0-151-generic
20.173 
20.173 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
20.438 RBFT-HOOK table found by source scan
20.438 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
20.438 RBFT-HOOK nic: eth0 address 10.77.0.72/24
20.459 RBFT-HOOK table check (source scan):
20.786 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
20.786 RBFT PASS signature: rBFT
20.786 RBFT PASS length: 234 bytes
20.786 RBFT PASS acpi_revision: 1
20.806 RBFT PASS checksum: all 234 bytes sum to 0
20.806 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
20.806 RBFT PASS magic: WRBT
20.806 RBFT PASS version: 1
20.806 RBFT PASS header_len: 116
20.806 RBFT PASS reserved: all reserved bytes are zero
20.806 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
20.806 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
20.806 RBFT PASS namespace: absent (as in version 1)
20.806 RBFT PASS rules: every rule of the field table holds
20.806 RBFT PASS entity: wrtest-p2-b0
20.806 RBFT PASS pool: winrbd
20.806 RBFT PASS image: wrtest-p2-b0
20.827 RBFT PASS image_id: 3941520e0799
20.827 RBFT PASS snapshot: absent, as expected
20.827 RBFT PASS auth: cephx
20.827 RBFT PASS msgr_mode: crc
20.827 RBFT PASS flags: key,static (0x6)
20.827 RBFT PASS flag_readonly: clear
20.827 RBFT PASS flag_key: set
20.827 RBFT PASS flag_nic_static: set
20.827 RBFT PASS flag_vlan: clear
20.827 RBFT PASS flag_fsid: clear
20.827 RBFT PASS flag_secure_required: clear
20.827 RBFT PASS key_type: aes
20.827 RBFT PASS key_len: 16
20.827 RBFT INFO key: present in the table (aes, 16 bytes), not printed
20.827 RBFT PASS mon_count: 1
20.827 RBFT PASS mon0: 10.77.0.10:3300
20.827 RBFT PASS fsid: none, as expected
20.848 RBFT PASS nic_mac: 52:54:00:77:12:c8
20.848 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
20.848 RBFT PASS nic_vlan: 0
20.848 RBFT PASS nic_mtu: 1500
20.848 RBFT PASS nic_family: 4
20.848 RBFT PASS nic_ip: 10.77.0.72
20.848 RBFT PASS nic_prefix: 24
20.848 RBFT PASS nic_gateway: zero, as expected
20.848 RBFT PASS nic_dns: zero, as expected
20.848 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ed 46 45 4e 53 59 53
20.848 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
20.848 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
20.868 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
20.868 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
20.868 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
20.868 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
20.868 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
20.868 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
20.868 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
20.868 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
20.889 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 39 34 31 35 32 30
20.889 RBFT DUMP 00c0: 65 30 37 39 39 00 04 00 e4 0c 0a 4d 00 0a 00 00
20.889 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
20.889 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
20.910 RBFT-RESULT PASS pass=40 fail=0 skip=0
20.910 WRBOOT-TABLE PASS
20.910 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
20.910 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
20.910 WRBOOT-EDD int13_dev81 mbr_signature=0x7d1f0002
20.930 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 fe80::5054:ff:fe77:12c8/64 
20.930 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
20.930 [    2.310092] reboot: Power down
