# tailts start epoch=1795462983.806
7.722 iPXE initialising devices...
7.742 
7.763 
7.783 
7.804 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.845 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.865 WRRUN-STUB
11.018 Configuring (net0 52:54:00:77:12:c8)...... ok
11.039 tftp://10.77.0.10/autoexec.ipxe... ok
11.059 WRRUN-BEGIN row=B0
11.121 Waiting for link-up on net0... ok
11.141 WRRUN-NET-OK
11.162 WRRUN-SAN-START sanhook
11.346 Registered SAN device 0x81
11.366 WRRUN-SAN-OK
11.386 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
11.428 rbd:   session: 25 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
11.489 rbd:   core: connections 2 (most 2), arena 263392 bytes, bulk 2627584 bytes; modes: 2 crc, 0 secure, 0 secure failures
11.530 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
11.612 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
11.633 WRRUN-LEAVE exit
11.653 WRRUN-END
15.112 GNU GRUB  version 2.14
15.112 
15.133 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
15.133       Press enter to boot the selected OS, `e' to edit the commands       
49.182       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
52.206 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
79.326 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
82.359 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
109.487 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
112.520 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
129.143 WRBOOT-TINY start kernel=6.8.0-151-generic
129.163 
129.163 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
129.428 RBFT-HOOK table found by source scan
129.428 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
129.428 RBFT-HOOK nic: eth0 address 10.77.0.72/24
129.428 RBFT-HOOK table check (source scan):
129.673 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
129.673 RBFT PASS signature: rBFT
129.673 RBFT PASS length: 234 bytes
129.673 RBFT PASS acpi_revision: 1
129.673 RBFT PASS checksum: all 234 bytes sum to 0
129.673 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
129.673 RBFT PASS magic: WRBT
129.673 RBFT PASS version: 1
129.673 RBFT PASS header_len: 116
129.693 RBFT PASS reserved: all reserved bytes are zero
129.693 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
129.693 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
129.693 RBFT PASS namespace: absent (as in version 1)
129.693 RBFT PASS rules: every rule of the field table holds
129.693 RBFT PASS entity: wrtest-p2-b0
129.693 RBFT PASS pool: winrbd
129.693 RBFT PASS image: wrtest-p2-b0
129.693 RBFT PASS image_id: 3941520e0799
129.693 RBFT PASS snapshot: absent, as expected
129.693 RBFT PASS auth: cephx
129.693 RBFT PASS msgr_mode: crc
129.693 RBFT PASS flags: key,static (0x6)
129.693 RBFT PASS flag_readonly: clear
129.693 RBFT PASS flag_key: set
129.693 RBFT PASS flag_nic_static: set
129.693 RBFT PASS flag_vlan: clear
129.693 RBFT PASS flag_fsid: clear
129.693 RBFT PASS flag_secure_required: clear
129.693 RBFT PASS key_type: aes
129.693 RBFT PASS key_len: 16
129.693 RBFT INFO key: present in the table (aes, 16 bytes), not printed
129.714 RBFT PASS mon_count: 1
129.714 RBFT PASS mon0: 10.77.0.10:3300
129.714 RBFT PASS fsid: none, as expected
129.714 RBFT PASS nic_mac: 52:54:00:77:12:c8
129.714 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
129.714 RBFT PASS nic_vlan: 0
129.714 RBFT PASS nic_mtu: 1500
129.714 RBFT PASS nic_family: 4
129.714 RBFT PASS nic_ip: 10.77.0.72
129.714 RBFT PASS nic_prefix: 24
129.714 RBFT PASS nic_gateway: zero, as expected
129.714 RBFT PASS nic_dns: zero, as expected
129.714 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ed 46 45 4e 53 59 53
129.714 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
129.714 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
129.714 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
129.714 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
129.714 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
129.734 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
129.734 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
129.734 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
129.734 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
129.734 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
129.734 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 39 34 31 35 32 30
129.734 RBFT DUMP 00c0: 65 30 37 39 39 00 04 00 e4 0c 0a 4d 00 0a 00 00
129.734 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
129.734 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
129.734 RBFT-RESULT PASS pass=40 fail=0 skip=0
129.734 WRBOOT-TABLE PASS
129.734 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
129.755 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
129.755 WRBOOT-EDD int13_dev81 mbr_signature=-
129.755 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 
129.755 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
129.755 [    1.821767] reboot: Power down
