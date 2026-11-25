# tailts start epoch=1795467045.362
10.098 iPXE initialising devices...
10.161 
10.204 
10.226 
10.415 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
10.779 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
10.865 WRRUN-STUB
14.010 Configuring (net0 52:54:00:77:12:d5)...... ok
14.428 tftp://10.77.0.10/autoexec.ipxe... ok
14.471 WRRUN-BEGIN row=B1
14.517 Waiting for link-up on net0... ok
14.538 WRRUN-NET-OK
14.602 WRRUN-SAN-START sanboot
14.750 rbd: stack high-water 2096 of 4096 bytes (2000 left)
14.772 rbd: core stack high-water 512 of 16384 bytes
14.968 rbd: stack high-water 2096 of 4096 bytes (2000 left)
15.014 rbd: core stack high-water 788 of 16384 bytes
16.108 rbd: stack high-water 2096 of 4096 bytes (2000 left)
16.181 rbd: core stack high-water 1304 of 16384 bytes
16.295 rbd: stack high-water 2096 of 4096 bytes (2000 left)
16.382 rbd: core stack high-water 1588 of 16384 bytes
18.079 Registered SAN device 0x80
18.165 Booting from SAN device 0x80
18.399 rbd: stack high-water 2780 of 4096 bytes (1316 left)
18.869 rbd: core stack high-water 1696 of 16384 bytes
47.029 GNU GRUB  version 2.14
47.029 
47.050 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
47.050       Press enter to boot the selected OS, `e' to edit the commands       
149.634       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: stack high-water 2932 of 4096 bytes (1164 left)
149.655 rbd: core stack high-water 1696 of 16384 bytes
308.232 Loading, please wait...
308.295 Starting systemd-udevd version 255.4-1ubuntu8.19
309.586 Begin: Loading essential drivers ... done.
309.608 Begin: Running /scripts/init-premount ... done.
310.231 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
310.254 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
312.623 RBFT-HOOK table found by source scan
312.644 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:d5
313.119 RBFT-HOOK nic: eth0 address 10.77.0.85/24
313.143 RBFT-HOOK table check (source scan):
314.068 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
314.068 RBFT PASS signature: rBFT
314.089 RBFT PASS length: 234 bytes
314.089 RBFT PASS acpi_revision: 1
314.089 RBFT PASS checksum: all 234 bytes sum to 0
314.089 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
314.089 RBFT PASS magic: WRBT
314.089 RBFT PASS version: 1
314.089 RBFT PASS header_len: 116
314.089 RBFT PASS reserved: all reserved bytes are zero
314.089 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
314.089 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
314.110 RBFT PASS namespace: absent (as in version 1)
314.110 RBFT PASS rules: every rule of the field table holds
314.110 RBFT PASS entity: wrtest-p2-b1
314.110 RBFT PASS pool: winrbd
314.110 RBFT PASS image: wrtest-p2-b1
314.110 RBFT PASS image_id: 38d9a2e0bcec
314.110 RBFT PASS snapshot: absent, as expected
314.110 RBFT PASS auth: cephx
314.110 RBFT PASS msgr_mode: crc
314.110 RBFT PASS flags: key,static (0x6)
314.110 RBFT PASS flag_readonly: clear
314.131 RBFT PASS flag_key: set
314.131 RBFT PASS flag_nic_static: set
314.131 RBFT PASS flag_vlan: clear
314.131 RBFT PASS flag_fsid: clear
314.131 RBFT PASS flag_secure_required: clear
314.131 RBFT PASS key_type: aes
314.131 RBFT PASS key_len: 16
314.131 RBFT INFO key: present in the table (aes, 16 bytes), not printed
314.131 RBFT PASS mon_count: 1
314.131 RBFT PASS mon0: 10.77.0.10:3300
314.131 RBFT PASS fsid: none, as expected
314.131 RBFT PASS nic_mac: 52:54:00:77:12:d5
314.153 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d5 exists in this guest
314.153 RBFT PASS nic_vlan: 0
314.153 RBFT PASS nic_mtu: 1500
314.153 RBFT PASS nic_family: 4
314.153 RBFT PASS nic_ip: 10.77.0.85
314.153 RBFT PASS nic_prefix: 24
314.153 RBFT PASS nic_gateway: zero, as expected
314.153 RBFT PASS nic_dns: zero, as expected
314.153 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 1b 46 45 4e 53 59 53
314.153 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
314.153 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
314.153 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
314.153 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d5 00 00
314.174 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 55 00 00 00 00 00 00 00 00
314.174 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
314.174 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
314.174 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
314.174 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
314.174 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
314.174 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
314.174 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
314.174 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
314.174 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
314.174 RBFT-RESULT PASS pass=40 fail=0 skip=0
314.196 WRBOOT-TABLE PASS
314.258 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
314.384 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
314.384 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
314.384 done.
314.406 Begin: Running /scripts/local-premount ... done.
344.532 Warning: fsck not present, so skipping root file system
344.575 done.
344.617 Begin: Running /scripts/local-bottom ... done.
344.638 Begin: Running /scripts/init-bottom ... done.
349.714 
349.714 Welcome to Ubuntu 24.04 LTS!
349.714 
355.732 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
355.732 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
355.753 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
355.753 [  OK  ] Created slice user.slice - User and Session Slice.
355.753 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
355.775 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
355.775 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
356.145          Expecting device dev-ttyS0.device - /dev/ttyS0...
356.145 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
356.145 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
356.145 [  OK  ] Reached target paths.target - Path Units.
356.145 [  OK  ] Reached target remote-fs.target - Remote File Systems.
356.167 [  OK  ] Reached target slices.target - Slice Units.
356.167 [  OK  ] Reached target swap.target - Swaps.
356.167 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
356.167 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
356.190 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
356.212 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
356.276 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
356.298 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
356.320          Mounting dev-hugepages.mount - Huge Pages File System...
356.342          Mounting dev-mqueue.mount - POSIX Message Queue File System...
356.364          Mounting sys-kernel-debug.mount - Kernel Debug File System...
356.364          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
356.406          Starting systemd-journald.service - Journal Service...
356.428          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
356.471          Starting modprobe@configfs.service - Load Kernel Module configfs...
356.494          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
356.515          Starting modprobe@drm.service - Load Kernel Module drm...
356.537          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
356.580          Starting modprobe@fuse.service - Load Kernel Module fuse...
356.580          Starting modprobe@loop.service - Load Kernel Module loop...
356.622          Starting systemd-modules-load.service - Load Kernel Modules...
356.622          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
356.643          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
356.664 [  OK  ] Started systemd-journald.service - Journal Service.
356.664 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
356.664 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
356.686 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
356.686 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
356.686 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
356.708 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
356.708 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
356.729 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
356.729 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
356.729 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
356.751 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
356.751 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
357.642          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
357.856          Mounting sys-kernel-config.mount - Kernel Configuration File System...
358.135          Starting systemd-sysctl.service - Apply Kernel Variables...
358.181          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
358.246 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
358.246 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
358.334 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
358.379          Starting systemd-random-seed.service - Load/Save OS Random Seed...
358.508 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
358.530 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
358.573 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
358.594 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
358.615          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
358.658 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
358.680 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
358.702          Mounting tmp.mount - /tmp...
358.724          Mounting var-cache.mount - /var/cache...
358.746          Mounting var-log.mount - /var/log...
358.789          Mounting var-tmp.mount - /var/tmp...
359.511          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
359.844 [  OK  ] Mounted tmp.mount - /tmp.
360.101 [  OK  ] Mounted var-cache.mount - /var/cache.
360.166 [  OK  ] Mounted var-log.mount - /var/log.
360.166 [  OK  ] Mounted var-tmp.mount - /var/tmp.
360.231 [  OK  ] Reached target local-fs.target - Local File Systems.
360.253 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
360.253 [  OK  ] Reached target sockets.target - Socket Units.
360.359          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
360.466 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
360.490          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
360.620 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
360.643          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
360.729 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
361.773 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
362.108 [  OK  ] Reached target sysinit.target - System Initialization.
362.108 [  OK  ] Started apt-daily.timer - Daily apt download activities.
362.108 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
362.108 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
362.108 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
362.130 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
362.130 [  OK  ] Started motd-news.timer - Message of the Day.
362.130 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
362.130 [  OK  ] Reached target timers.target - Timer Units.
362.130 [  OK  ] Reached target basic.target - Basic System.
362.172          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
362.236          Starting getty-static.service - geâ¦bus and logind are not available...
362.278          Starting systemd-user-sessions.service - Permit User Sessions...
362.384          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
362.469 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
362.553 [  OK  ] Started getty@tty1.service - Getty on tty1.
362.636 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
363.054 [  OK  ] Started getty@tty2.service - Getty on tty2.
363.667 [  OK  ] Started getty@tty3.service - Getty on tty3.
363.755 [  OK  ] Started getty@tty4.service - Getty on tty4.
364.379 [  OK  ] Started getty@tty5.service - Getty on tty5.
364.403 WRBOOT-NET eth0 mac=52:54:00:77:12:d5 10.77.0.85/24 fe80::5054:ff:fe77:12d5/64 
364.511 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
364.642 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
364.749 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
364.770 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
