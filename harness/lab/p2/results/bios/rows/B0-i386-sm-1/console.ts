# tailts start epoch=1795465447.206
10.237 iPXE initialising devices...
10.278 
10.278 
10.299 
10.340 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
10.361 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
10.382 WRRUN-STUB
13.550 Configuring (net0 52:54:00:77:12:d4)...... ok
13.767 tftp://10.77.0.10/autoexec.ipxe... ok
13.787 WRRUN-BEGIN row=B0
13.870 Waiting for link-up on net0... ok
13.891 WRRUN-NET-OK
13.932 WRRUN-SAN-START sanhook
13.974 rbd: stack high-water 2120 of 4096 bytes (1976 left)
13.995 rbd: core stack high-water 512 of 16384 bytes
14.037 rbd: stack high-water 2120 of 4096 bytes (1976 left)
14.057 rbd: core stack high-water 788 of 16384 bytes
14.078 rbd: stack high-water 2120 of 4096 bytes (1976 left)
14.099 rbd: core stack high-water 1304 of 16384 bytes
14.119 rbd: stack high-water 2120 of 4096 bytes (1976 left)
14.140 rbd: core stack high-water 1588 of 16384 bytes
14.304 Registered SAN device 0x81
14.325 WRRUN-SAN-OK
14.345 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
14.366 rbd:   session: 30 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
14.387 rbd:   core stack: 1696 of 16384 bytes used
14.448 rbd:   core: connections 2 (most 2), arena 260128 bytes, bulk 2627584 bytes; modes: 2 crc, 0 secure, 0 secure failures
14.490 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
14.552 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
14.719 rbd: stack high-water 2120 of 4096 bytes (1976 left)
14.740 WRRUN-LEAVE exit
14.761 WRRUN-END
18.242 GNU GRUB  version 2.14
18.242 
18.263 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
18.263       Press enter to boot the selected OS, `e' to edit the commands       
52.540       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
55.553 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
82.700 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
85.726 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
112.831 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
115.860 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
132.984 WRBOOT-TINY start kernel=6.8.0-151-generic
133.025 
133.025 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
133.292 RBFT-HOOK table found by source scan
133.292 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:d4
133.313 RBFT-HOOK nic: eth0 address 10.77.0.84/24
133.313 RBFT-HOOK table check (source scan):
133.558 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
133.558 RBFT PASS signature: rBFT
133.558 RBFT PASS length: 234 bytes
133.558 RBFT PASS acpi_revision: 1
133.558 RBFT PASS checksum: all 234 bytes sum to 0
133.558 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
133.558 RBFT PASS magic: WRBT
133.558 RBFT PASS version: 1
133.579 RBFT PASS header_len: 116
133.579 RBFT PASS reserved: all reserved bytes are zero
133.579 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
133.579 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
133.579 RBFT PASS namespace: absent (as in version 1)
133.579 RBFT PASS rules: every rule of the field table holds
133.579 RBFT PASS entity: wrtest-p2-b0
133.579 RBFT PASS pool: winrbd
133.579 RBFT PASS image: wrtest-p2-b0
133.579 RBFT PASS image_id: 3941520e0799
133.579 RBFT PASS snapshot: absent, as expected
133.600 RBFT PASS auth: cephx
133.662 RBFT PASS msgr_mode: crc
133.662 RBFT PASS flags: key,static (0x6)
133.662 RBFT PASS flag_readonly: clear
133.662 RBFT PASS flag_key: set
133.662 RBFT PASS flag_nic_static: set
133.662 RBFT PASS flag_vlan: clear
133.662 RBFT PASS flag_fsid: clear
133.662 RBFT PASS flag_secure_required: clear
133.662 RBFT PASS key_type: aes
133.662 RBFT PASS key_len: 16
133.662 RBFT INFO key: present in the table (aes, 16 bytes), not printed
133.682 RBFT PASS mon_count: 1
133.682 RBFT PASS mon0: 10.77.0.10:3300
133.682 RBFT PASS fsid: none, as expected
133.682 RBFT PASS nic_mac: 52:54:00:77:12:d4
133.682 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d4 exists in this guest
133.682 RBFT PASS nic_vlan: 0
133.682 RBFT PASS nic_mtu: 1500
133.682 RBFT PASS nic_family: 4
133.682 RBFT PASS nic_ip: 10.77.0.84
133.682 RBFT PASS nic_prefix: 24
133.682 RBFT PASS nic_gateway: zero, as expected
133.682 RBFT PASS nic_dns: zero, as expected
133.682 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 d5 46 45 4e 53 59 53
133.682 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
133.682 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
133.703 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
133.703 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d4 00 00
133.703 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 54 00 00 00 00 00 00 00 00
133.703 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
133.703 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
133.703 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
133.703 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
133.703 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
133.703 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 39 34 31 35 32 30
133.703 RBFT DUMP 00c0: 65 30 37 39 39 00 04 00 e4 0c 0a 4d 00 0a 00 00
133.724 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
133.724 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
133.724 RBFT-RESULT PASS pass=40 fail=0 skip=0
133.724 WRBOOT-TABLE PASS
133.724 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
133.724 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
133.724 WRBOOT-EDD int13_dev81 mbr_signature=-
133.744 WRBOOT-NET eth0 mac=52:54:00:77:12:d4 10.77.0.84/24 
133.744 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
133.744 [    2.240463] reboot: Power down
