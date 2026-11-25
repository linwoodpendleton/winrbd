# tailts start epoch=1795467425.067
0.737 iPXE initialising devices...
1.529 
1.529 
1.529 
1.529 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
1.550 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
1.550 WRRUN-STUB
4.702 Configuring (net0 52:54:00:77:11:49)...... ok
4.766 tftp://10.0.2.2/autoexec.ipxe... ok
4.766 WRRUN-BEGIN row=B2
4.811 Waiting for link-up on net1... ok
4.811 WRRUN-NET-OK
4.811 WRRUN-SAN-START sanboot
4.854 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.854 rbd: core stack high-water 512 of 16384 bytes
4.876 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.876 rbd: core stack high-water 760 of 16384 bytes
4.942 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.963 rbd: core stack high-water 1304 of 16384 bytes
4.963 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.985 rbd: core stack high-water 1588 of 16384 bytes
5.927 Registered SAN device 0x80
5.948 Booting from SAN device 0x80
6.012 rbd: stack high-water 2672 of 4096 bytes (1424 left)
6.054 rbd: core stack high-water 1696 of 16384 bytes
976.007 rbd: stack high-water 2812 of 4096 bytes (1284 left)
976.028 rbd: core stack high-water 1696 of 16384 bytes
980.030 GNU GRUB  version 2.14
980.030 
980.074 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
980.074       Press enter to boot the selected OS, `e' to edit the commands       
1153.871       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
1153.914 Starting systemd-udevd version 255.4-1ubuntu8.19
1154.580 Begin: Loading essential drivers ... done.
1154.601 Begin: Running /scripts/init-premount ... done.
1154.622 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
1154.622 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
1154.933 RBFT-HOOK table found by source scan
1154.933 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
1154.933 RBFT-HOOK nic: eth1 address 10.77.0.73/24
1154.933 RBFT-HOOK table check (source scan):
1155.225 RBFT INFO source: scan: found at physical address 0x9e140 (1 valid copy/copies)
1155.225 RBFT PASS signature: rBFT
1155.225 RBFT PASS length: 234 bytes
1155.225 RBFT PASS acpi_revision: 1
1155.225 RBFT PASS checksum: all 234 bytes sum to 0
1155.247 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
1155.247 RBFT PASS magic: WRBT
1155.247 RBFT PASS version: 1
1155.247 RBFT PASS header_len: 116
1155.247 RBFT PASS reserved: all reserved bytes are zero
1155.247 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
1155.247 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
1155.247 RBFT PASS namespace: absent (as in version 1)
1155.247 RBFT PASS rules: every rule of the field table holds
1155.247 RBFT PASS entity: wrtest-p2-b2
1155.247 RBFT PASS pool: winrbd
1155.247 RBFT PASS image: wrtest-p2-b2
1155.269 RBFT PASS image_id: 3956afc63637
1155.269 RBFT PASS snapshot: absent, as expected
1155.269 RBFT PASS auth: cephx
1155.269 RBFT PASS msgr_mode: crc
1155.269 RBFT PASS flags: key,static (0x6)
1155.269 RBFT PASS flag_readonly: clear
1155.269 RBFT PASS flag_key: set
1155.269 RBFT PASS flag_nic_static: set
1155.269 RBFT PASS flag_vlan: clear
1155.269 RBFT PASS flag_fsid: clear
1155.269 RBFT PASS flag_secure_required: clear
1155.269 RBFT PASS key_type: aes
1155.269 RBFT PASS key_len: 16
1155.269 RBFT INFO key: present in the table (aes, 16 bytes), not printed
1155.269 RBFT PASS mon_count: 1
1155.269 RBFT PASS mon0: 10.77.0.10:3300
1155.290 RBFT PASS fsid: none, as expected
1155.290 RBFT PASS nic_mac: 52:54:00:77:12:c9
1155.290 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
1155.290 RBFT PASS nic_vlan: 0
1155.290 RBFT PASS nic_mtu: 1500
1155.290 RBFT PASS nic_family: 4
1155.290 RBFT PASS nic_ip: 10.77.0.73
1155.290 RBFT PASS nic_prefix: 24
1155.290 RBFT PASS nic_gateway: zero, as expected
1155.290 RBFT PASS nic_dns: zero, as expected
1155.290 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 95 46 45 4e 53 59 53
1155.290 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
1155.312 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
1155.312 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
1155.312 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
1155.312 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
1155.312 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
1155.312 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
1155.312 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
1155.312 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
1155.312 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
1155.333 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 39 35 36 61 66 63
1155.333 RBFT DUMP 00c0: 36 33 36 33 37 00 04 00 e4 0c 0a 4d 00 0a 00 00
1155.333 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
1155.333 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
1155.333 RBFT-RESULT PASS pass=40 fail=0 skip=0
1155.333 WRBOOT-TABLE PASS
1155.440 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
1155.524 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
1155.524 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
1155.524 done.
1155.545 Begin: Running /scripts/local-premount ... done.
1185.741 Warning: fsck not present, so skipping root file system
1185.762 done.
1185.805 Begin: Running /scripts/local-bottom ... done.
1185.848 Begin: Running /scripts/init-bottom ... done.
1188.307 
1188.307 Welcome to Ubuntu 24.04 LTS!
1188.307 
1190.019 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
1190.019 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
1190.040 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
1190.040 [  OK  ] Created slice user.slice - User and Session Slice.
1190.040 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
1190.040 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
1190.062 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
1190.062          Expecting device dev-ttyS0.device - /dev/ttyS0...
1190.062 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
1190.062 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
1190.062 [  OK  ] Reached target paths.target - Path Units.
1190.062 [  OK  ] Reached target remote-fs.target - Remote File Systems.
1190.084 [  OK  ] Reached target slices.target - Slice Units.
1190.084 [  OK  ] Reached target swap.target - Swaps.
1190.084 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
1190.084 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
1190.084 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
1190.084 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
1190.105 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
1190.105 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
1190.126          Mounting dev-hugepages.mount - Huge Pages File System...
1190.147          Mounting dev-mqueue.mount - POSIX Message Queue File System...
1190.168          Mounting sys-kernel-debug.mount - Kernel Debug File System...
1190.168          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
1190.189          Starting systemd-journald.service - Journal Service...
1190.210          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
1190.232          Starting modprobe@configfs.service - Load Kernel Module configfs...
1190.232          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
1190.254          Starting modprobe@drm.service - Load Kernel Module drm...
1190.276          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
1190.297          Starting modprobe@fuse.service - Load Kernel Module fuse...
1190.319          Starting modprobe@loop.service - Load Kernel Module loop...
1190.361          Starting systemd-modules-load.service - Load Kernel Modules...
1190.383          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
1190.405          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
1190.426 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
1190.426 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
1190.426 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
1190.448 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
1190.448 [  OK  ] Started systemd-journald.service - Journal Service.
1190.469 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
1190.491 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
1190.491 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
1190.513 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
1190.513 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
1190.535 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
1190.535 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
1190.556 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
1190.599          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
1190.642          Mounting sys-kernel-config.mount - Kernel Configuration File System...
1190.642          Starting systemd-sysctl.service - Apply Kernel Variables...
1190.663          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
1190.685 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
1190.685 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
1190.685 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
1190.727          Starting systemd-random-seed.service - Load/Save OS Random Seed...
1190.812 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
1190.833 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
1190.915 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
1190.936          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
1190.957 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
1190.978 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
1190.978 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
1190.999          Mounting tmp.mount - /tmp...
1191.020          Mounting var-cache.mount - /var/cache...
1191.041          Mounting var-log.mount - /var/log...
1191.041          Mounting var-tmp.mount - /var/tmp...
1191.062          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
1191.062 [  OK  ] Mounted tmp.mount - /tmp.
1191.083 [  OK  ] Mounted var-cache.mount - /var/cache.
1191.083 [  OK  ] Mounted var-log.mount - /var/log.
1191.083 [  OK  ] Mounted var-tmp.mount - /var/tmp.
1191.083 [  OK  ] Reached target local-fs.target - Local File Systems.
1191.103 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
1191.103 [  OK  ] Reached target sockets.target - Socket Units.
1191.145          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
1191.187 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
1191.209          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
1191.313 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
1191.334          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
1191.397 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
1191.544 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
1191.544 [  OK  ] Reached target sysinit.target - System Initialization.
1191.544 [  OK  ] Started apt-daily.timer - Daily apt download activities.
1191.565 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
1191.565 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
1191.585 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
1191.585 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
1191.585 [  OK  ] Started motd-news.timer - Message of the Day.
1191.585 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
1191.607 [  OK  ] Reached target timers.target - Timer Units.
1191.607 [  OK  ] Reached target basic.target - Basic System.
1191.628          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
1191.671          Starting getty-static.service - geâ¦bus and logind are not available...
1191.692          Starting systemd-user-sessions.service - Permit User Sessions...
1191.713          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
1191.818 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
1191.839 [  OK  ] Started getty@tty1.service - Getty on tty1.
1191.860 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
1191.860 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
1192.217 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
1192.217 WRBOOT-EDD int13_dev81 mbr_signature=-
1192.538 [  OK  ] Started getty@tty2.service - Getty on tty2.
1192.581 [  OK  ] Started getty@tty3.service - Getty on tty3.
1192.646 [  OK  ] Started getty@tty4.service - Getty on tty4.
1192.753 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
1192.795 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
1192.836 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
1192.836 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
1192.857 [  OK  ] Started getty@tty5.service - Getty on tty5.
1192.878 [  OK  ] Started getty@tty6.service - Getty on tty6.
1192.899 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
1192.920 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
1192.941 [  OK  ] Reached target getty.target - Login Prompts.
1192.941 [  OK  ] Reached target multi-user.target - Multi-User System.
1192.941 [  OK  ] Reached target graphical.target - Graphical Interface.
1192.983          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
1193.046 [  OK  ] Listening on systemd-rfkill.socketâ¦ll Switch Status /dev/rfkill Watch.
1193.046 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
