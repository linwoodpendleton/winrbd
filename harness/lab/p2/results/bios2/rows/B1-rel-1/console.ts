# tailts start epoch=1795481413.078
8.351 iPXE initialising devices...
8.392 
8.413 
8.434 
8.475 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.517 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.538 WRRUN-STUB
11.679 Configuring (net0 52:54:00:77:12:c7)...... ok
11.741 tftp://10.77.0.10/autoexec.ipxe... ok
11.761 WRRUN-BEGIN row=B1
11.844 Waiting for link-up on net0... ok
11.865 WRRUN-NET-OK
11.906 WRRUN-SAN-START sanboot
12.155 Registered SAN device 0x80
12.176 Booting from SAN device 0x80
16.570 GNU GRUB  version 2.14
16.570 
16.611 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
16.611       Press enter to boot the selected OS, `e' to edit the commands       
49.513       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
49.575 Starting systemd-udevd version 255.4-1ubuntu8.19
50.381 Begin: Loading essential drivers ... done.
50.381 Begin: Running /scripts/init-premount ... done.
50.422 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
50.422 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
50.936 RBFT-HOOK table found by source scan
50.936 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
50.957 RBFT-HOOK nic: eth0 address 10.77.0.71/24
50.957 RBFT-HOOK table check (source scan):
51.287 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
51.287 RBFT PASS signature: rBFT
51.287 RBFT PASS length: 234 bytes
51.308 RBFT PASS acpi_revision: 1
51.308 RBFT PASS checksum: all 234 bytes sum to 0
51.308 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
51.308 RBFT PASS magic: WRBT
51.308 RBFT PASS version: 1
51.308 RBFT PASS header_len: 116
51.308 RBFT PASS reserved: all reserved bytes are zero
51.308 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
51.329 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
51.329 RBFT PASS namespace: absent (as in version 1)
51.329 RBFT PASS rules: every rule of the field table holds
51.329 RBFT PASS entity: wrtest-p2-b1
51.329 RBFT PASS pool: winrbd
51.329 RBFT PASS image: wrtest-p2-b1
51.329 RBFT PASS image_id: 3fae3418fe30
51.329 RBFT PASS snapshot: absent, as expected
51.350 RBFT PASS auth: cephx
51.350 RBFT PASS msgr_mode: crc
51.350 RBFT PASS flags: key,static (0x6)
51.350 RBFT PASS flag_readonly: clear
51.350 RBFT PASS flag_key: set
51.350 RBFT PASS flag_nic_static: set
51.350 RBFT PASS flag_vlan: clear
51.350 RBFT PASS flag_fsid: clear
51.350 RBFT PASS flag_secure_required: clear
51.350 RBFT PASS key_type: aes
51.350 RBFT PASS key_len: 16
51.370 RBFT INFO key: present in the table (aes, 16 bytes), not printed
51.370 RBFT PASS mon_count: 1
51.370 RBFT PASS mon0: 10.77.0.10:3300
51.370 RBFT PASS fsid: none, as expected
51.370 RBFT PASS nic_mac: 52:54:00:77:12:c7
51.370 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
51.370 RBFT PASS nic_vlan: 0
51.370 RBFT PASS nic_mtu: 1500
51.370 RBFT PASS nic_family: 4
51.370 RBFT PASS nic_ip: 10.77.0.71
51.370 RBFT PASS nic_prefix: 24
51.391 RBFT PASS nic_gateway: zero, as expected
51.391 RBFT PASS nic_dns: zero, as expected
51.391 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
51.391 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
51.391 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
51.391 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
51.412 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
51.412 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
51.412 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
51.412 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
51.412 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
51.412 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
51.412 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
51.433 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
51.433 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
51.433 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
51.433 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
51.433 RBFT-RESULT PASS pass=40 fail=0 skip=0
51.433 WRBOOT-TABLE PASS
51.518 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
51.765 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
51.765 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
51.765 done.
51.765 Begin: Running /scripts/local-premount ... done.
81.930 Warning: fsck not present, so skipping root file system
81.972 done.
82.033 Begin: Running /scripts/local-bottom ... done.
82.115 Begin: Running /scripts/init-bottom ... done.
90.857 
90.857 Welcome to Ubuntu 24.04 LTS!
90.857 
94.070 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
94.070 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
94.091 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
94.091 [  OK  ] Created slice user.slice - User and Session Slice.
94.111 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
94.111 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
94.111 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
94.111          Expecting device dev-ttyS0.device - /dev/ttyS0...
94.133 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
94.133 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
94.133 [  OK  ] Reached target paths.target - Path Units.
94.133 [  OK  ] Reached target remote-fs.target - Remote File Systems.
94.133 [  OK  ] Reached target slices.target - Slice Units.
94.153 [  OK  ] Reached target swap.target - Swaps.
94.153 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
94.153 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
94.153 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
94.174 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
94.174 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
94.174 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
94.216          Mounting dev-hugepages.mount - Huge Pages File System...
94.237          Mounting dev-mqueue.mount - POSIX Message Queue File System...
94.237          Mounting sys-kernel-debug.mount - Kernel Debug File System...
94.237          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
94.258          Starting systemd-journald.service - Journal Service...
94.279          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
94.300          Starting modprobe@configfs.service - Load Kernel Module configfs...
94.300          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
94.321          Starting modprobe@drm.service - Load Kernel Module drm...
94.321          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
94.342          Starting modprobe@fuse.service - Load Kernel Module fuse...
94.342          Starting modprobe@loop.service - Load Kernel Module loop...
94.383          Starting systemd-modules-load.service - Load Kernel Modules...
94.383          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
94.404          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
94.404 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
94.424 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
94.424 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
94.424 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
94.424 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
94.445 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
94.445 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
94.445          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
94.466          Mounting sys-kernel-config.mount - Kernel Configuration File System...
94.466          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
94.717 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
94.738          Starting systemd-sysctl.service - Apply Kernel Variables...
95.294 [  OK  ] Started systemd-journald.service - Journal Service.
96.569 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
96.569 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
96.569 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
96.590 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
96.611 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
96.611 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
96.673 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
96.740          Starting systemd-random-seed.service - Load/Save OS Random Seed...
96.781 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
96.802 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
96.906 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
97.009 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
97.030          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
97.071 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
97.092 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
97.135          Mounting tmp.mount - /tmp...
97.177          Mounting var-cache.mount - /var/cache...
97.404          Mounting var-log.mount - /var/log...
97.445          Mounting var-tmp.mount - /var/tmp...
97.487          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
97.487 [  OK  ] Mounted tmp.mount - /tmp.
97.508 [  OK  ] Mounted var-cache.mount - /var/cache.
97.508 [  OK  ] Mounted var-log.mount - /var/log.
97.508 [  OK  ] Mounted var-tmp.mount - /var/tmp.
97.529 [  OK  ] Reached target local-fs.target - Local File Systems.
97.715 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
97.715 [  OK  ] Reached target sockets.target - Socket Units.
97.757          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
97.841 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
97.862          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
97.945 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
97.965          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
98.027 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
98.027 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
98.048 [  OK  ] Reached target sysinit.target - System Initialization.
98.048 [  OK  ] Started apt-daily.timer - Daily apt download activities.
98.048 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
98.069 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
98.069 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
98.069 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
98.069 [  OK  ] Started motd-news.timer - Message of the Day.
98.090 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
98.090 [  OK  ] Reached target timers.target - Timer Units.
98.090 [  OK  ] Reached target basic.target - Basic System.
98.111          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
98.132          Starting getty-static.service - geâ¦bus and logind are not available...
98.174          Starting systemd-user-sessions.service - Permit User Sessions...
98.195          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
98.259 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
98.301 [  OK  ] Started getty@tty1.service - Getty on tty1.
98.343 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
98.488 [  OK  ] Started getty@tty2.service - Getty on tty2.
98.509 [  OK  ] Started getty@tty3.service - Getty on tty3.
98.530 [  OK  ] Started getty@tty4.service - Getty on tty4.
98.551 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
98.572 [  OK  ] Started getty@tty5.service - Getty on tty5.
98.613 [  OK  ] Started getty@tty6.service - Getty on tty6.
98.634 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
98.655 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
98.697 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
98.821 [  OK  ] Reached target getty.target - Login Prompts.
98.926 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
98.926 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
98.926 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
98.946 [  OK  ] Reached target multi-user.target - Multi-User System.
98.946 [  OK  ] Reached target graphical.target - Graphical Interface.
98.967          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
99.051 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
