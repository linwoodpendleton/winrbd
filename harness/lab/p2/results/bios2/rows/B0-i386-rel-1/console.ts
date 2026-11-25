# tailts start epoch=1795480757.962
8.402 iPXE initialising devices...
8.422 
8.443 
8.464 
8.505 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.525 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.546 WRRUN-STUB
11.761 Configuring (net0 52:54:00:77:12:c8)...... ok
11.803 tftp://10.77.0.10/autoexec.ipxe... ok
11.823 WRRUN-BEGIN row=B0
11.885 Waiting for link-up on net0... ok
11.906 WRRUN-NET-OK
11.906 WRRUN-SAN-START sanhook
12.214 Registered SAN device 0x81
12.235 WRRUN-SAN-OK
12.851 xbft: rBFT at 0x9a880, 233 bytes, inside the 0x80000-0xfffff window
12.872 xbft: 1 table(s) use 240 of the 2048 bytes of the area (0 refused)
12.892 rbd: image winrbd/wrtest-p2-b0: open, 1 device(s), 4194304 blocks of 512 bytes
12.934 rbd:   session: 38 pumps, 0 cancels (most rounds 0), 0 reopens, 0 stall closes
12.955 rbd:   core stack: 1696 of 16384 bytes used
12.997 rbd:   core: connections 3 (most 3), arena 260128 bytes, bulk 2627584 bytes; modes: 3 crc, 0 secure, 0 secure failures
13.058 rbd:   osd: 4 ops done, 0 resent, 0 failed; in flight 0 (most 1), requests 0 (most 1); 0 session resets, zombies 0 of 0 bytes
13.100 rbd:   readahead: 2 reads: 0 hits, 0 waits, 2 misses; 0 windows, 0 prefetches (0 landed, 0 failed, 0 dropped), 0 lines valid
13.121 WRRUN-LEAVE exit
13.141 WRRUN-END
13.245 rbd: net0: an RBD drive is hooked and iPXE is exiting over a UNDI network device: the PXE ROM stops its network stack when iPXE returns, and reads of the drive will then stall (boot with sanboot, or use ipxe.pxe with a native driver)
16.844 GNU GRUB  version 2.14
16.844 
16.886 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
16.886       Press enter to boot the selected OS, `e' to edit the commands       
51.262       before booting or `c' for a command-line.                            *winrbd tiny (row B0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
54.303 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
81.414 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
84.428 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
111.562 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
114.588 rbd: the cluster has not answered for 30 seconds, closing the path: no monitor could be reached (WR_E_MON_UNREACHABLE)
131.978 WRBOOT-TINY start kernel=6.8.0-151-generic
132.019 
132.019 RBFT-HOOK start: map=0 src=scan rootpart=2 require=0
132.347 RBFT-HOOK table found by source scan
132.368 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c8
132.368 RBFT-HOOK nic: eth0 address 10.77.0.72/24
132.368 RBFT-HOOK table check (source scan):
132.717 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
132.738 RBFT PASS signature: rBFT
132.738 RBFT PASS length: 233 bytes
132.738 RBFT PASS acpi_revision: 1
132.738 RBFT PASS checksum: all 233 bytes sum to 0
132.759 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
132.759 RBFT PASS magic: WRBT
132.759 RBFT PASS version: 1
132.759 RBFT PASS header_len: 116
132.759 RBFT PASS reserved: all reserved bytes are zero
132.759 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
132.759 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (81 bytes of area)
132.759 RBFT PASS namespace: absent (as in version 1)
132.759 RBFT PASS rules: every rule of the field table holds
132.759 RBFT PASS entity: wrtest-p2-b0
132.759 RBFT PASS pool: winrbd
132.759 RBFT PASS image: wrtest-p2-b0
132.780 RBFT PASS image_id: 3fa2de52cac
132.780 RBFT PASS snapshot: absent, as expected
132.780 RBFT PASS auth: cephx
132.780 RBFT PASS msgr_mode: crc
132.780 RBFT PASS flags: key,static (0x6)
132.780 RBFT PASS flag_readonly: clear
132.780 RBFT PASS flag_key: set
132.780 RBFT PASS flag_nic_static: set
132.780 RBFT PASS flag_vlan: clear
132.780 RBFT PASS flag_fsid: clear
132.780 RBFT PASS flag_secure_required: clear
132.780 RBFT PASS key_type: aes
132.780 RBFT PASS key_len: 16
132.780 RBFT INFO key: present in the table (aes, 16 bytes), not printed
132.780 RBFT PASS mon_count: 1
132.780 RBFT PASS mon0: 10.77.0.10:3300
132.780 RBFT PASS fsid: none, as expected
132.780 RBFT PASS nic_mac: 52:54:00:77:12:c8
132.801 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c8 exists in this guest
132.801 RBFT PASS nic_vlan: 0
132.801 RBFT PASS nic_mtu: 1500
132.801 RBFT PASS nic_family: 4
132.801 RBFT PASS nic_ip: 10.77.0.72
132.801 RBFT PASS nic_prefix: 24
132.801 RBFT PASS nic_gateway: zero, as expected
132.801 RBFT PASS nic_dns: zero, as expected
132.801 RBFT DUMP 0000: 72 42 46 54 e9 00 00 00 01 2c 46 45 4e 53 59 53
132.801 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
132.801 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
132.801 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
132.801 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c8 00 00
132.801 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 48 00 00 00 00 00 00 00 00
132.801 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
132.821 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
132.821 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
132.821 RBFT DUMP 0090: 2d 00 41 00 00 00 00 00 77 72 74 65 73 74 2d 70
132.821 RBFT DUMP 00a0: 32 2d 62 30 00 77 69 6e 72 62 64 00 77 72 74 65
132.821 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 30 00 33 66 61 32 64 65 35
132.821 RBFT DUMP 00c0: 32 63 61 63 00 04 00 e4 0c 0a 4d 00 0a 00 00 00
132.821 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 .. .. .. .. .. .. ..
132.821 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. ..
132.821 RBFT-RESULT PASS pass=40 fail=0 skip=0
132.821 WRBOOT-TABLE PASS
132.821 RBFT-HOOK map=0: not mapping the image; root stays as given on the command line
132.842 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
132.842 WRBOOT-EDD int13_dev81 mbr_signature=-
132.842 WRBOOT-NET eth0 mac=52:54:00:77:12:c8 10.77.0.72/24 fe80::5054:ff:fe77:12c8/64 
132.842 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
132.863 [    2.407123] reboot: Power down
