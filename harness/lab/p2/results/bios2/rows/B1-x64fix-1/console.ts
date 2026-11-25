# tailts start epoch=1795482439.326
7.687 iPXE initialising devices...
7.728 
7.748 
7.769 
7.789 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.831 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.851 WRRUN-STUB
10.994 Configuring (net0 52:54:00:77:12:c7)...... ok
11.015 tftp://10.77.0.10/autoexec.ipxe... ok
11.035 WRRUN-BEGIN row=B1
11.097 Waiting for link-up on net0... ok
11.117 WRRUN-NET-OK
11.138 WRRUN-SAN-START sanboot
11.179 rbd: stack high-water 3360 of 8192 bytes (4832 left)
11.240 rbd: stack high-water 3960 of 8192 bytes (4232 left)
11.281 rbd: stack high-water 4344 of 8192 bytes (3848 left)
11.383 rbd: stack high-water 4648 of 8192 bytes (3544 left)
11.404 Registered SAN device 0x80
11.424 Booting from SAN device 0x80
11.465 rbd: stack high-water 4864 of 8192 bytes (3328 left)
12.569 rbd: stack high-water 5608 of 8192 bytes (2584 left)
14.121 GNU GRUB  version 2.14
14.121 
14.141 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.141       Press enter to boot the selected OS, `e' to edit the commands       
27.699       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
27.720 Starting systemd-udevd version 255.4-1ubuntu8.19
28.302 Begin: Loading essential drivers ... done.
28.323 Begin: Running /scripts/init-premount ... done.
28.365 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
28.365 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
28.676 RBFT-HOOK table found by source scan
28.697 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
28.697 RBFT-HOOK nic: eth0 address 10.77.0.71/24
28.697 RBFT-HOOK table check (source scan):
28.969 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
28.990 RBFT PASS signature: rBFT
28.990 RBFT PASS length: 234 bytes
28.990 RBFT PASS acpi_revision: 1
28.990 RBFT PASS checksum: all 234 bytes sum to 0
28.990 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
28.990 RBFT PASS magic: WRBT
28.990 RBFT PASS version: 1
28.990 RBFT PASS header_len: 116
28.990 RBFT PASS reserved: all reserved bytes are zero
28.990 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
28.990 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
28.990 RBFT PASS namespace: absent (as in version 1)
28.990 RBFT PASS rules: every rule of the field table holds
28.990 RBFT PASS entity: wrtest-p2-b1
28.990 RBFT PASS pool: winrbd
29.012 RBFT PASS image: wrtest-p2-b1
29.012 RBFT PASS image_id: 3fae3418fe30
29.012 RBFT PASS snapshot: absent, as expected
29.012 RBFT PASS auth: cephx
29.012 RBFT PASS msgr_mode: crc
29.012 RBFT PASS flags: key,static (0x6)
29.012 RBFT PASS flag_readonly: clear
29.012 RBFT PASS flag_key: set
29.012 RBFT PASS flag_nic_static: set
29.012 RBFT PASS flag_vlan: clear
29.012 RBFT PASS flag_fsid: clear
29.012 RBFT PASS flag_secure_required: clear
29.012 RBFT PASS key_type: aes
29.012 RBFT PASS key_len: 16
29.012 RBFT INFO key: present in the table (aes, 16 bytes), not printed
29.012 RBFT PASS mon_count: 1
29.012 RBFT PASS mon0: 10.77.0.10:3300
29.012 RBFT PASS fsid: none, as expected
29.012 RBFT PASS nic_mac: 52:54:00:77:12:c7
29.033 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
29.033 RBFT PASS nic_vlan: 0
29.033 RBFT PASS nic_mtu: 1500
29.033 RBFT PASS nic_family: 4
29.033 RBFT PASS nic_ip: 10.77.0.71
29.033 RBFT PASS nic_prefix: 24
29.033 RBFT PASS nic_gateway: zero, as expected
29.033 RBFT PASS nic_dns: zero, as expected
29.033 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
29.033 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
29.033 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
29.033 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
29.033 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
29.054 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
29.054 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.054 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.054 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
29.054 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
29.054 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
29.054 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
29.054 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
29.054 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
29.054 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
29.054 RBFT-RESULT PASS pass=40 fail=0 skip=0
29.076 WRBOOT-TABLE PASS
29.138 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
29.201 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
29.222 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
29.222 done.
29.222 Begin: Running /scripts/local-premount ... done.
59.774 Warning: fsck not present, so skipping root file system
59.918 done.
59.981 Begin: Running /scripts/local-bottom ... done.
60.002 Begin: Running /scripts/init-bottom ... done.
67.854 
67.854 Welcome to Ubuntu 24.04 LTS!
67.854 
70.022 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
70.022 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
70.045 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
70.045 [  OK  ] Created slice user.slice - User and Session Slice.
70.045 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
70.045 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
70.045 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
70.045          Expecting device dev-ttyS0.device - /dev/ttyS0...
70.066 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
70.066 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
70.066 [  OK  ] Reached target paths.target - Path Units.
70.066 [  OK  ] Reached target remote-fs.target - Remote File Systems.
70.066 [  OK  ] Reached target slices.target - Slice Units.
70.066 [  OK  ] Reached target swap.target - Swaps.
70.066 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
70.087 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
70.087 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
70.087 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
70.087 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
70.087 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
70.108          Mounting dev-hugepages.mount - Huge Pages File System...
70.129          Mounting dev-mqueue.mount - POSIX Message Queue File System...
70.150          Mounting sys-kernel-debug.mount - Kernel Debug File System...
70.150          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
70.171          Starting systemd-journald.service - Journal Service...
70.191          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
70.212          Starting modprobe@configfs.service - Load Kernel Module configfs...
70.233          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
70.254          Starting modprobe@drm.service - Load Kernel Module drm...
70.408          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
70.449          Starting modprobe@fuse.service - Load Kernel Module fuse...
70.449          Starting modprobe@loop.service - Load Kernel Module loop...
70.740          Starting systemd-modules-load.service - Load Kernel Modules...
70.740          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
70.761          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
70.782 [  OK  ] Started systemd-journald.service - Journal Service.
70.782 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
70.782 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
70.803 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
70.803 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
70.803 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
70.803 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
70.824 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
70.824 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
70.824 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
70.845 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
70.845 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
70.866 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
70.907          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
70.928          Mounting sys-kernel-config.mount - Kernel Configuration File System...
70.949          Starting systemd-sysctl.service - Apply Kernel Variables...
70.971          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
70.971 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
70.992 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
70.992 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
71.033          Starting systemd-random-seed.service - Load/Save OS Random Seed...
71.054 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
71.076 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
71.096 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
71.117          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
71.138 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
71.138 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
71.159          Mounting tmp.mount - /tmp...
71.180          Mounting var-cache.mount - /var/cache...
71.222          Mounting var-log.mount - /var/log...
71.222          Mounting var-tmp.mount - /var/tmp...
71.243          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
71.243 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
71.264 [  OK  ] Mounted tmp.mount - /tmp.
71.264 [  OK  ] Mounted var-cache.mount - /var/cache.
71.264 [  OK  ] Mounted var-log.mount - /var/log.
71.264 [  OK  ] Mounted var-tmp.mount - /var/tmp.
71.286 [  OK  ] Reached target local-fs.target - Local File Systems.
71.286 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
71.286 [  OK  ] Reached target sockets.target - Socket Units.
71.307          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
71.349 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
71.370          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
71.433 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
71.454          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
71.475 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
71.787 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
71.808 [  OK  ] Reached target sysinit.target - System Initialization.
71.808 [  OK  ] Started apt-daily.timer - Daily apt download activities.
71.808 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
71.829 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
71.829 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
71.850 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
71.850 [  OK  ] Started motd-news.timer - Message of the Day.
71.975 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
71.975 [  OK  ] Reached target timers.target - Timer Units.
71.975 [  OK  ] Reached target basic.target - Basic System.
71.996          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
71.996          Starting getty-static.service - geâ¦bus and logind are not available...
72.037          Starting systemd-user-sessions.service - Permit User Sessions...
72.079          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
72.101 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
72.164 [  OK  ] Started getty@tty1.service - Getty on tty1.
72.207 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
72.228 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
72.270 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
72.708 [  OK  ] Started getty@tty2.service - Getty on tty2.
72.729 [  OK  ] Started getty@tty3.service - Getty on tty3.
72.750 [  OK  ] Started getty@tty4.service - Getty on tty4.
72.792 [  OK  ] Started getty@tty5.service - Getty on tty5.
72.792 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
72.792 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
72.834 [  OK  ] Started getty@tty6.service - Getty on tty6.
72.834 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
72.855 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
72.875 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
72.896 [  OK  ] Reached target getty.target - Login Prompts.
72.896 [  OK  ] Reached target multi-user.target - Multi-User System.
72.896 [  OK  ] Reached target graphical.target - Graphical Interface.
72.917          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
72.980 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
