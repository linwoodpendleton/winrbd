# tailts start epoch=1795480687.104
0.205 iPXE initialising devices...
0.411 
0.411 
0.411 
0.435 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.435 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.435 WRRUN-STUB
3.563 Configuring (net0 52:54:00:77:11:4a)...... ok
3.604 tftp://10.0.2.2/autoexec.ipxe... ok
3.604 WRRUN-BEGIN row=B3
3.666 Waiting for link-up on net1... ok
3.666 WRRUN-NET-OK
3.687 WRRUN-SAN-START sanboot
3.687 rbd: DIAG-IF core calls 1, with interrupts enabled 0
3.708 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.708 rbd: core stack high-water 512 of 16384 bytes
3.728 rbd: DIAG-IF core calls 6, with interrupts enabled 0
3.728 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.728 rbd: core stack high-water 788 of 16384 bytes
3.770 rbd: DIAG-IF core calls 11, with interrupts enabled 0
3.790 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.832 rbd: core stack high-water 1304 of 16384 bytes
3.853 rbd: DIAG-IF core calls 13, with interrupts enabled 0
3.874 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.895 rbd: core stack high-water 1588 of 16384 bytes
4.101 Registered SAN device 0x80
4.122 Booting from SAN device 0x80
4.163 rbd: DIAG-IF core calls 78, with interrupts enabled 0
4.184 rbd: stack high-water 2676 of 4096 bytes (1420 left)
4.205 rbd: core stack high-water 1696 of 16384 bytes
5.122 rbd: DIAG-IF core calls 512, with interrupts enabled 0
5.967 rbd: DIAG-IF core calls 1024, with interrupts enabled 0
6.482 rbd: DIAG-IF core calls 1536, with interrupts enabled 0
7.121 GNU GRUB  version 2.14
7.121 
7.163 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
7.163       Press enter to boot the selected OS, `e' to edit the commands       
10.022       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: DIAG-IF core calls 2048, with interrupts enabled 0
10.333 rbd: DIAG-IF core calls 2560, with interrupts enabled 0
10.374 rbd: DIAG-IF core calls 3072, with interrupts enabled 0
10.457 rbd: DIAG-IF core calls 3584, with interrupts enabled 0
10.814 rbd: DIAG-IF core calls 4096, with interrupts enabled 0
10.919 rbd: DIAG-IF core calls 4608, with interrupts enabled 0
11.001 rbd: DIAG-IF core calls 5120, with interrupts enabled 0
11.063 rbd: DIAG-IF core calls 5632, with interrupts enabled 0
11.125 rbd: DIAG-IF core calls 6144, with interrupts enabled 0
11.413 rbd: DIAG-IF core calls 6656, with interrupts enabled 0
11.454 rbd: DIAG-IF core calls 7168, with interrupts enabled 0
11.722 rbd: DIAG-IF core calls 7680, with interrupts enabled 0
11.805 rbd: DIAG-IF core calls 8192, with interrupts enabled 0
11.929 rbd: DIAG-IF core calls 8704, with interrupts enabled 0
12.032 rbd: DIAG-IF core calls 9216, with interrupts enabled 0
12.094 rbd: DIAG-IF core calls 9728, with interrupts enabled 0
12.177 rbd: DIAG-IF core calls 10240, with interrupts enabled 0
12.444 rbd: DIAG-IF core calls 10752, with interrupts enabled 0
12.735 rbd: DIAG-IF core calls 11264, with interrupts enabled 0
12.797 rbd: DIAG-IF core calls 11776, with interrupts enabled 0
12.942 rbd: DIAG-IF core calls 12288, with interrupts enabled 0
16.168 Loading, please wait...
16.190 Starting systemd-udevd version 255.4-1ubuntu8.19
17.208 Begin: Loading essential drivers ... done.
17.208 Begin: Running /scripts/init-premount ... done.
17.249 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
17.249 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
17.703 RBFT-HOOK table found by source scan
17.703 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
17.703 RBFT-HOOK nic: eth1 address 10.77.0.74/24
17.703 RBFT-HOOK table check (source scan):
17.991 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
17.991 RBFT PASS signature: rBFT
17.991 RBFT PASS length: 234 bytes
17.991 RBFT PASS acpi_revision: 1
17.991 RBFT PASS checksum: all 234 bytes sum to 0
17.991 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
17.991 RBFT PASS magic: WRBT
17.991 RBFT PASS version: 1
17.991 RBFT PASS header_len: 116
17.991 RBFT PASS reserved: all reserved bytes are zero
17.991 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.991 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.991 RBFT PASS namespace: absent (as in version 1)
18.012 RBFT PASS rules: every rule of the field table holds
18.012 RBFT PASS entity: wrtest-p2-b3
18.012 RBFT PASS pool: winrbd
18.012 RBFT PASS image: wrtest-p2-b3
18.012 RBFT PASS image_id: 3fc6592539a3
18.012 RBFT PASS snapshot: absent, as expected
18.012 RBFT PASS auth: cephx
18.012 RBFT PASS msgr_mode: crc
18.012 RBFT PASS flags: key,static (0x6)
18.012 RBFT PASS flag_readonly: clear
18.012 RBFT PASS flag_key: set
18.012 RBFT PASS flag_nic_static: set
18.012 RBFT PASS flag_vlan: clear
18.012 RBFT PASS flag_fsid: clear
18.012 RBFT PASS flag_secure_required: clear
18.012 RBFT PASS key_type: aes
18.032 RBFT PASS key_len: 16
18.032 RBFT INFO key: present in the table (aes, 16 bytes), not printed
18.032 RBFT PASS mon_count: 1
18.032 RBFT PASS mon0: 10.77.0.10:3300
18.032 RBFT PASS fsid: none, as expected
18.032 RBFT PASS nic_mac: 52:54:00:77:12:ca
18.032 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
18.032 RBFT PASS nic_vlan: 0
18.032 RBFT PASS nic_mtu: 1500
18.032 RBFT PASS nic_family: 4
18.032 RBFT PASS nic_ip: 10.77.0.74
18.032 RBFT PASS nic_prefix: 24
18.032 RBFT PASS nic_gateway: zero, as expected
18.053 RBFT PASS nic_dns: zero, as expected
18.053 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 94 46 45 4e 53 59 53
18.053 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
18.053 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
18.053 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
18.053 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
18.053 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
18.053 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.053 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.074 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
18.074 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
18.074 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
18.074 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 66 63 36 35 39 32
18.074 RBFT DUMP 00c0: 35 33 39 61 33 00 04 00 e4 0c 0a 4d 00 0a 00 00
18.074 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
18.074 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
18.094 RBFT-RESULT PASS pass=40 fail=0 skip=0
18.094 WRBOOT-TABLE PASS
18.136 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
18.218 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
18.218 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
18.218 done.
18.218 Begin: Running /scripts/local-premount ... done.
48.303 Warning: fsck not present, so skipping root file system
48.323 done.
48.344 Begin: Running /scripts/local-bottom ... done.
48.364 Begin: Running /scripts/init-bottom ... done.
50.247 
50.247 Welcome to Ubuntu 24.04 LTS!
50.247 
51.642 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
51.642 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
51.642 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
51.642 [  OK  ] Created slice user.slice - User and Session Slice.
51.663 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
51.663 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
51.663 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
51.663          Expecting device dev-ttyS0.device - /dev/ttyS0...
51.663 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
51.684 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
51.684 [  OK  ] Reached target paths.target - Path Units.
51.684 [  OK  ] Reached target remote-fs.target - Remote File Systems.
51.684 [  OK  ] Reached target slices.target - Slice Units.
51.684 [  OK  ] Reached target swap.target - Swaps.
51.705 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
51.705 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
51.705 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
51.705 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
51.726 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
51.726 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
51.767          Mounting dev-hugepages.mount - Huge Pages File System...
51.767          Mounting dev-mqueue.mount - POSIX Message Queue File System...
51.788          Mounting sys-kernel-debug.mount - Kernel Debug File System...
51.788          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
51.809          Starting systemd-journald.service - Journal Service...
51.830          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
51.830          Starting modprobe@configfs.service - Load Kernel Module configfs...
51.851          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
51.851          Starting modprobe@drm.service - Load Kernel Module drm...
51.871          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
51.892          Starting modprobe@fuse.service - Load Kernel Module fuse...
51.913          Starting modprobe@loop.service - Load Kernel Module loop...
51.954          Starting systemd-modules-load.service - Load Kernel Modules...
51.954          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
51.954          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
51.974 [  OK  ] Started systemd-journald.service - Journal Service.
51.974 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
51.974 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
51.974 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
51.995 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
51.995 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
51.995 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
51.995 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
52.016 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
52.016 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
52.037 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
52.037 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
52.058 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
52.078          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
52.099          Mounting sys-kernel-config.mount - Kernel Configuration File System...
52.120          Starting systemd-sysctl.service - Apply Kernel Variables...
52.141          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
52.162 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
52.162 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
52.162 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
52.204          Starting systemd-random-seed.service - Load/Save OS Random Seed...
52.245 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
52.287 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
52.349 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
52.370          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
52.391 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
52.411 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
52.411 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
52.432          Mounting tmp.mount - /tmp...
52.453          Mounting var-cache.mount - /var/cache...
52.453          Mounting var-log.mount - /var/log...
52.473          Mounting var-tmp.mount - /var/tmp...
52.618          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
52.618 [  OK  ] Mounted tmp.mount - /tmp.
52.618 [  OK  ] Mounted var-cache.mount - /var/cache.
52.638 [  OK  ] Mounted var-log.mount - /var/log.
52.638 [  OK  ] Mounted var-tmp.mount - /var/tmp.
52.638 [  OK  ] Reached target local-fs.target - Local File Systems.
52.659 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
52.659 [  OK  ] Reached target sockets.target - Socket Units.
52.680          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
52.700 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
52.721          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
52.845 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
52.866          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
52.907 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
52.989 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
52.989 [  OK  ] Reached target sysinit.target - System Initialization.
52.989 [  OK  ] Started apt-daily.timer - Daily apt download activities.
53.010 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
53.010 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
53.010 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
53.010 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
53.010 [  OK  ] Started motd-news.timer - Message of the Day.
53.010 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
53.031 [  OK  ] Reached target timers.target - Timer Units.
53.031 [  OK  ] Reached target basic.target - Basic System.
53.051          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
53.051          Starting getty-static.service - geâ¦bus and logind are not available...
53.072          Starting systemd-user-sessions.service - Permit User Sessions...
53.093          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
53.155 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
53.175 [  OK  ] Started getty@tty1.service - Getty on tty1.
53.279 [  OK  ] Started getty@tty2.service - Getty on tty2.
53.341 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
53.424 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
53.444 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
53.632 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
53.674 [  OK  ] Started getty@tty3.service - Getty on tty3.
53.674 [  OK  ] Started getty@tty4.service - Getty on tty4.
53.694 [  OK  ] Started getty@tty5.service - Getty on tty5.
53.735 [  OK  ] Started getty@tty6.service - Getty on tty6.
53.756 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
53.756 [  OK  ] Reached target getty.target - Login Prompts.
53.777 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
53.777 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
53.777 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
53.798 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
53.798 [  OK  ] Reached target multi-user.target - Multi-User System.
53.798 [  OK  ] Reached target graphical.target - Graphical Interface.
53.819          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
53.860 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
