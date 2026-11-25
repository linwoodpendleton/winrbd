# tailts start epoch=1795480600.598
7.846 iPXE initialising devices...
7.867 
7.888 
7.908 
7.950 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.971 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.991 WRRUN-STUB
11.075 Configuring (net0 52:54:00:77:12:c7)...... ok
11.095 tftp://10.77.0.10/autoexec.ipxe... ok
11.116 WRRUN-BEGIN row=B1
11.178 Waiting for link-up on net0... ok
11.198 WRRUN-NET-OK
11.219 WRRUN-SAN-START sanboot
11.260 rbd: DIAG-IF core calls 1, with interrupts enabled 0
11.281 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.302 rbd: core stack high-water 512 of 16384 bytes
11.323 rbd: DIAG-IF core calls 6, with interrupts enabled 0
11.364 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.384 rbd: core stack high-water 788 of 16384 bytes
11.405 rbd: DIAG-IF core calls 10, with interrupts enabled 0
11.446 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.467 rbd: core stack high-water 1304 of 16384 bytes
11.487 rbd: DIAG-IF core calls 12, with interrupts enabled 0
11.508 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.528 rbd: core stack high-water 1588 of 16384 bytes
11.631 Registered SAN device 0x80
11.652 Booting from SAN device 0x80
11.672 rbd: DIAG-IF core calls 53, with interrupts enabled 0
11.713 rbd: stack high-water 2784 of 4096 bytes (1312 left)
11.734 rbd: core stack high-water 1696 of 16384 bytes
13.831 rbd: DIAG-IF core calls 512, with interrupts enabled 0
14.470 GNU GRUB  version 2.14
14.470 
14.491 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.491       Press enter to boot the selected OS, `e' to edit the commands       
17.259       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: DIAG-IF core calls 1024, with interrupts enabled 0
17.892 rbd: DIAG-IF core calls 1536, with interrupts enabled 0
18.506 rbd: DIAG-IF core calls 2048, with interrupts enabled 0
19.221 rbd: DIAG-IF core calls 2560, with interrupts enabled 0
19.652 rbd: DIAG-IF core calls 3072, with interrupts enabled 0
19.897 rbd: DIAG-IF core calls 3584, with interrupts enabled 0
20.572 rbd: DIAG-IF core calls 4096, with interrupts enabled 0
21.144 rbd: DIAG-IF core calls 4608, with interrupts enabled 0
21.532 rbd: DIAG-IF core calls 5120, with interrupts enabled 0
22.207 rbd: DIAG-IF core calls 5632, with interrupts enabled 0
22.739 rbd: DIAG-IF core calls 6144, with interrupts enabled 0
25.584 Loading, please wait...
25.625 Starting systemd-udevd version 255.4-1ubuntu8.19
26.218 Begin: Loading essential drivers ... done.
26.218 Begin: Running /scripts/init-premount ... done.
26.259 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
26.259 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
26.544 RBFT-HOOK table found by source scan
26.565 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
26.565 RBFT-HOOK nic: eth0 address 10.77.0.71/24
26.565 RBFT-HOOK table check (source scan):
26.831 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
26.831 RBFT PASS signature: rBFT
26.831 RBFT PASS length: 234 bytes
26.831 RBFT PASS acpi_revision: 1
26.831 RBFT PASS checksum: all 234 bytes sum to 0
26.831 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
26.831 RBFT PASS magic: WRBT
26.831 RBFT PASS version: 1
26.831 RBFT PASS header_len: 116
26.831 RBFT PASS reserved: all reserved bytes are zero
26.831 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
26.831 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
26.831 RBFT PASS namespace: absent (as in version 1)
26.831 RBFT PASS rules: every rule of the field table holds
26.852 RBFT PASS entity: wrtest-p2-b1
26.852 RBFT PASS pool: winrbd
26.852 RBFT PASS image: wrtest-p2-b1
26.852 RBFT PASS image_id: 3fae3418fe30
26.852 RBFT PASS snapshot: absent, as expected
26.852 RBFT PASS auth: cephx
26.852 RBFT PASS msgr_mode: crc
26.852 RBFT PASS flags: key,static (0x6)
26.852 RBFT PASS flag_readonly: clear
26.852 RBFT PASS flag_key: set
26.852 RBFT PASS flag_nic_static: set
26.852 RBFT PASS flag_vlan: clear
26.852 RBFT PASS flag_fsid: clear
26.852 RBFT PASS flag_secure_required: clear
26.852 RBFT PASS key_type: aes
26.852 RBFT PASS key_len: 16
26.852 RBFT INFO key: present in the table (aes, 16 bytes), not printed
26.852 RBFT PASS mon_count: 1
26.852 RBFT PASS mon0: 10.77.0.10:3300
26.872 RBFT PASS fsid: none, as expected
26.872 RBFT PASS nic_mac: 52:54:00:77:12:c7
26.872 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
26.872 RBFT PASS nic_vlan: 0
26.872 RBFT PASS nic_mtu: 1500
26.872 RBFT PASS nic_family: 4
26.872 RBFT PASS nic_ip: 10.77.0.71
26.872 RBFT PASS nic_prefix: 24
26.872 RBFT PASS nic_gateway: zero, as expected
26.872 RBFT PASS nic_dns: zero, as expected
26.872 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
26.872 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
26.872 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
26.872 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
26.893 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
26.893 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
26.893 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.893 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.893 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
26.893 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
26.914 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
26.914 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
26.914 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
26.914 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
26.914 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
26.914 RBFT-RESULT PASS pass=40 fail=0 skip=0
26.914 WRBOOT-TABLE PASS
26.955 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
27.016 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
27.016 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
27.016 done.
27.016 Begin: Running /scripts/local-premount ... done.
61.160 Warning: fsck not present, so skipping root file system
61.222 done.
61.264 Begin: Running /scripts/local-bottom ... done.
61.306 Begin: Running /scripts/init-bottom ... done.
69.194 
69.194 Welcome to Ubuntu 24.04 LTS!
69.194 
70.928 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
70.928 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
70.928 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
70.949 [  OK  ] Created slice user.slice - User and Session Slice.
70.949 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
70.949 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
70.949 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
70.949          Expecting device dev-ttyS0.device - /dev/ttyS0...
70.949 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
70.970 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
70.970 [  OK  ] Reached target paths.target - Path Units.
70.970 [  OK  ] Reached target remote-fs.target - Remote File Systems.
71.034 [  OK  ] Reached target slices.target - Slice Units.
71.117 [  OK  ] Reached target swap.target - Swaps.
71.117 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
71.117 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
71.117 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
71.117 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
71.138 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
71.138 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
71.180          Mounting dev-hugepages.mount - Huge Pages File System...
71.180          Mounting dev-mqueue.mount - POSIX Message Queue File System...
71.201          Mounting sys-kernel-debug.mount - Kernel Debug File System...
71.221          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
71.221          Starting systemd-journald.service - Journal Service...
71.242          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
71.263          Starting modprobe@configfs.service - Load Kernel Module configfs...
71.284          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
71.305          Starting modprobe@drm.service - Load Kernel Module drm...
71.326          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
71.346          Starting modprobe@fuse.service - Load Kernel Module fuse...
71.471          Starting modprobe@loop.service - Load Kernel Module loop...
71.533          Starting systemd-modules-load.service - Load Kernel Modules...
71.554          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
71.554          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
71.554 [  OK  ] Started systemd-journald.service - Journal Service.
71.575 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
71.575 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
71.575 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
71.596 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
71.596 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
71.596 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
71.617 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
71.617 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
71.638 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
71.638 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
71.659 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
71.659 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
71.700          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
71.721          Mounting sys-kernel-config.mount - Kernel Configuration File System...
71.742          Starting systemd-sysctl.service - Apply Kernel Variables...
71.763          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
71.783 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
71.783 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
71.783 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
71.825          Starting systemd-random-seed.service - Load/Save OS Random Seed...
71.866 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
71.887 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
71.948 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
71.969          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
72.178 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
72.199 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
72.199 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
72.219          Mounting tmp.mount - /tmp...
72.240          Mounting var-cache.mount - /var/cache...
72.261          Mounting var-log.mount - /var/log...
72.282          Mounting var-tmp.mount - /var/tmp...
72.302          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
72.302 [  OK  ] Mounted tmp.mount - /tmp.
72.302 [  OK  ] Mounted var-cache.mount - /var/cache.
72.302 [  OK  ] Mounted var-log.mount - /var/log.
72.302 [  OK  ] Mounted var-tmp.mount - /var/tmp.
72.323 [  OK  ] Reached target local-fs.target - Local File Systems.
72.323 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
72.323 [  OK  ] Reached target sockets.target - Socket Units.
72.344          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
72.385 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
72.406          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
72.467 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
72.488          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
72.529 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
72.673 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
72.673 [  OK  ] Reached target sysinit.target - System Initialization.
72.694 [  OK  ] Started apt-daily.timer - Daily apt download activities.
72.694 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
72.694 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
72.715 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
72.715 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
72.715 [  OK  ] Started motd-news.timer - Message of the Day.
72.715 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
72.715 [  OK  ] Reached target timers.target - Timer Units.
72.736 [  OK  ] Reached target basic.target - Basic System.
72.736          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
72.777          Starting getty-static.service - geâ¦bus and logind are not available...
72.777          Starting systemd-user-sessions.service - Permit User Sessions...
72.798          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
72.860 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
72.901 [  OK  ] Started getty@tty1.service - Getty on tty1.
72.901 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
73.251 [  OK  ] Started getty@tty2.service - Getty on tty2.
73.314 [  OK  ] Started getty@tty3.service - Getty on tty3.
73.503 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
73.544 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
73.544 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
73.544 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
73.565 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
73.627 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
73.648 [  OK  ] Started getty@tty4.service - Getty on tty4.
73.668 [  OK  ] Started getty@tty5.service - Getty on tty5.
73.668 [  OK  ] Started getty@tty6.service - Getty on tty6.
73.710 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
73.710 [  OK  ] Reached target getty.target - Login Prompts.
73.710 [  OK  ] Reached target multi-user.target - Multi-User System.
73.710 [  OK  ] Reached target graphical.target - Graphical Interface.
73.730          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
73.772 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
