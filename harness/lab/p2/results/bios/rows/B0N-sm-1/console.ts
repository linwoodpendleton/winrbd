# tailts start epoch=1795463621.943
8.338 iPXE initialising devices...
8.400 
8.421 
8.441 
8.462 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.503 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.524 WRRUN-STUB
11.628 Configuring (net0 52:54:00:77:12:c8)...... ok
11.669 tftp://10.77.0.10/autoexec.ipxe... ok
11.690 WRRUN-BEGIN row=B0
11.752 Waiting for link-up on net0... ok
11.773 WRRUN-NET-OK
12.140 WRRUN-SAN-START sanhook
12.224 rbd: stack monitor: the stack is not iPXE's own (frame 0x7ffd5578, internal stack 0xffffffffeb547e30 to 0xffffffffeb549e30): not painted
12.512 Registered SAN device 0x81
12.532 WRRUN-SAN-OK
12.553 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.594 rbd:   session: 35 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.635 rbd:   core: connections 2 (most 2), arena 263392 bytes, bulk 2627584 bytes; modes: 2 crc, 0 secure, 0 secure failures
12.718 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
12.780 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
12.862 WRRUN-LEAVE exit
12.905 WRRUN-END
13.357 GNU GRUB  version 2.14
13.357 
13.377 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.398       Press enter to boot the selected OS, `e' to edit the commands       
18.044       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 WRBOOT-TINY start kernel=6.8.0-151-generic
18.065 
18.065 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
18.353 RBFT-HOOK table found by source scan
18.353 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
18.373 RBFT-HOOK nic: eth0 address 10.77.0.72/24
18.373 RBFT-HOOK table check (source scan):
18.639 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
18.639 RBFT PASS signature: rBFT
18.639 RBFT PASS length: 234 bytes
18.639 RBFT PASS acpi_revision: 1
18.639 RBFT PASS checksum: all 234 bytes sum to 0
18.639 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
18.660 RBFT PASS magic: WRBT
18.660 RBFT PASS version: 1
18.660 RBFT PASS header_len: 116
18.660 RBFT PASS reserved: all reserved bytes are zero
18.660 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
18.660 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
18.660 RBFT PASS namespace: absent (as in version 1)
18.660 RBFT PASS rules: every rule of the field table holds
18.660 RBFT PASS entity: wrtest-p2-b0
18.660 RBFT PASS pool: winrbd
18.660 RBFT PASS image: wrtest-p2-b0
18.660 RBFT PASS image_id: 3941520e0799
18.660 RBFT PASS snapshot: absent, as expected
18.660 RBFT PASS auth: cephx
18.660 RBFT PASS msgr_mode: crc
18.660 RBFT PASS flags: key,static (0x6)
18.660 RBFT PASS flag_readonly: clear
18.660 RBFT PASS flag_key: set
18.680 RBFT PASS flag_nic_static: set
18.680 RBFT PASS flag_vlan: clear
18.680 RBFT PASS flag_fsid: clear
18.680 RBFT PASS flag_secure_required: clear
18.680 RBFT PASS key_type: aes
18.680 RBFT PASS key_len: 16
18.680 RBFT INFO key: present in the table (aes, 16 bytes), not printed
18.680 RBFT PASS mon_count: 1
18.680 RBFT PASS mon0: 10.77.0.10:3300
18.680 RBFT PASS fsid: none, as expected
18.680 RBFT PASS nic_mac: 52:54:00:77:12:c8
18.680 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
18.680 RBFT PASS nic_vlan: 0
18.680 RBFT PASS nic_mtu: 1500
18.680 RBFT PASS nic_family: 4
18.680 RBFT PASS nic_ip: 10.77.0.72
18.680 RBFT PASS nic_prefix: 24
18.680 RBFT PASS nic_gateway: zero, as expected
18.680 RBFT PASS nic_dns: zero, as expected
18.680 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ed 46 45 4e 53 59 53
18.680 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
18.701 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
18.701 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
18.701 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
18.701 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
18.701 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.701 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.701 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
18.701 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
18.701 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
18.701 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 39 34 31 35 32 30
18.701 RBFT DUMP 00c0: 65 30 37 39 39 00 04 00 e4 0c 0a 4d 00 0a 00 00
18.701 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
18.701 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
18.722 RBFT-RESULT PASS pass=40 fail=0 skip=0
18.722 WRBOOT-TABLE PASS
18.722 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
18.722 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
18.722 WRBOOT-EDD int13_dev81 mbr_signature=0x7d1f0002
18.743 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 
18.743 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
18.743 [    2.200619] reboot: Power down
