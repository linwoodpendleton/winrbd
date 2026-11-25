# tailts start epoch=1795464926.639
0.041 iPXE initialising devices...
0.290 
0.290 
0.290 
0.290 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.310 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.310 WRRUN-STUB
3.441 Configuring (net0 52:54:00:77:11:4a)...... ok
3.441 tftp://10.0.2.2/autoexec.ipxe... ok
3.441 WRRUN-BEGIN row=B3
3.482 Waiting for link-up on net1... ok
3.482 WRRUN-NET-OK
3.482 WRRUN-SAN-START sanboot
3.707 Registered SAN device 0x80
3.707 Booting from SAN device 0x80
5.447 GNU GRUB  version 2.14
5.447 
5.467 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.467       Press enter to boot the selected OS, `e' to edit the commands       
32.402       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
32.423 Starting systemd-udevd version 255.4-1ubuntu8.19
33.037 Begin: Loading essential drivers ... done.
33.037 Begin: Running /scripts/init-premount ... done.
33.078 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
33.078 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
33.343 RBFT-HOOK table found by source scan
33.343 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
33.343 RBFT-HOOK nic: eth1 address 10.77.0.74/24
33.343 RBFT-HOOK table check (source scan):
33.609 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
33.609 RBFT PASS signature: rBFT
33.609 RBFT PASS length: 234 bytes
33.609 RBFT PASS acpi_revision: 1
33.629 RBFT PASS checksum: all 234 bytes sum to 0
33.629 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
33.629 RBFT PASS magic: WRBT
33.629 RBFT PASS version: 1
33.629 RBFT PASS header_len: 116
33.629 RBFT PASS reserved: all reserved bytes are zero
33.629 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
33.629 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
33.629 RBFT PASS namespace: absent (as in version 1)
33.629 RBFT PASS rules: every rule of the field table holds
33.629 RBFT PASS entity: wrtest-p2-b3
33.629 RBFT PASS pool: winrbd
33.629 RBFT PASS image: wrtest-p2-b3
33.629 RBFT PASS image_id: 39648e0b332d
33.629 RBFT PASS snapshot: absent, as expected
33.629 RBFT PASS auth: cephx
33.650 RBFT PASS msgr_mode: crc
33.650 RBFT PASS flags: key,static (0x6)
33.650 RBFT PASS flag_readonly: clear
33.650 RBFT PASS flag_key: set
33.650 RBFT PASS flag_nic_static: set
33.650 RBFT PASS flag_vlan: clear
33.650 RBFT PASS flag_fsid: clear
33.650 RBFT PASS flag_secure_required: clear
33.650 RBFT PASS key_type: aes
33.650 RBFT PASS key_len: 16
33.650 RBFT INFO key: present in the table (aes, 16 bytes), not printed
33.650 RBFT PASS mon_count: 1
33.650 RBFT PASS mon0: 10.77.0.10:3300
33.650 RBFT PASS fsid: none, as expected
33.650 RBFT PASS nic_mac: 52:54:00:77:12:ca
33.650 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
33.650 RBFT PASS nic_vlan: 0
33.650 RBFT PASS nic_mtu: 1500
33.670 RBFT PASS nic_family: 4
33.670 RBFT PASS nic_ip: 10.77.0.74
33.670 RBFT PASS nic_prefix: 24
33.670 RBFT PASS nic_gateway: zero, as expected
33.670 RBFT PASS nic_dns: zero, as expected
33.670 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
33.670 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
33.670 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
33.670 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
33.670 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
33.670 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
33.670 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
33.670 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
33.691 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
33.691 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
33.691 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
33.691 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
33.691 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
33.691 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
33.691 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
33.691 RBFT-RESULT PASS pass=40 fail=0 skip=0
33.691 WRBOOT-TABLE PASS
33.773 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
34.020 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
34.020 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
34.020 done.
34.040 Begin: Running /scripts/local-premount ... done.
64.151 Warning: fsck not present, so skipping root file system
64.172 done.
64.213 Begin: Running /scripts/local-bottom ... done.
64.234 Begin: Running /scripts/init-bottom ... done.
65.630 
65.630 Welcome to Ubuntu 24.04 LTS!
65.630 
66.693 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
66.693 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
66.714 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
66.714 [  OK  ] Created slice user.slice - User and Session Slice.
66.714 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
66.714 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
66.714 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
66.714          Expecting device dev-ttyS0.device - /dev/ttyS0...
66.714 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
66.735 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
66.735 [  OK  ] Reached target paths.target - Path Units.
66.735 [  OK  ] Reached target remote-fs.target - Remote File Systems.
66.735 [  OK  ] Reached target slices.target - Slice Units.
66.735 [  OK  ] Reached target swap.target - Swaps.
66.735 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
66.755 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
66.755 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
66.755 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
66.755 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
66.755 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
66.776          Mounting dev-hugepages.mount - Huge Pages File System...
66.797          Mounting dev-mqueue.mount - POSIX Message Queue File System...
66.797          Mounting sys-kernel-debug.mount - Kernel Debug File System...
66.797          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
66.817          Starting systemd-journald.service - Journal Service...
66.838          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
66.858          Starting modprobe@configfs.service - Load Kernel Module configfs...
67.043          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
67.043          Starting modprobe@drm.service - Load Kernel Module drm...
67.064          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
67.064          Starting modprobe@fuse.service - Load Kernel Module fuse...
67.085          Starting modprobe@loop.service - Load Kernel Module loop...
67.105          Starting systemd-modules-load.service - Load Kernel Modules...
67.126          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
67.126          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
67.146 [  OK  ] Started systemd-journald.service - Journal Service.
67.146 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
67.146 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
67.167 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
67.167 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
67.187 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
67.187 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
67.187 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
67.208 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
67.228 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
67.228 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
67.249 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
67.249 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
67.270 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
67.290          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
67.311          Mounting sys-kernel-config.mount - Kernel Configuration File System...
67.331          Starting systemd-random-seed.service - Load/Save OS Random Seed...
67.331          Starting systemd-sysctl.service - Apply Kernel Variables...
67.352          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
67.372 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
67.372 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
67.393 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
67.455 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
67.537 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
67.537          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
67.537 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
67.558 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
67.579 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
67.579          Mounting tmp.mount - /tmp...
67.600          Mounting var-cache.mount - /var/cache...
67.620          Mounting var-log.mount - /var/log...
67.620          Mounting var-tmp.mount - /var/tmp...
67.641          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
67.641 [  OK  ] Mounted tmp.mount - /tmp.
67.641 [  OK  ] Mounted var-cache.mount - /var/cache.
67.641 [  OK  ] Mounted var-log.mount - /var/log.
67.641 [  OK  ] Mounted var-tmp.mount - /var/tmp.
67.662 [  OK  ] Reached target local-fs.target - Local File Systems.
67.662 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
67.662 [  OK  ] Reached target sockets.target - Socket Units.
67.682          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
67.703 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
67.724          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
67.785 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
67.806          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
67.827 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
67.991 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
67.991 [  OK  ] Reached target sysinit.target - System Initialization.
68.013 [  OK  ] Started apt-daily.timer - Daily apt download activities.
68.013 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
68.013 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
68.013 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
68.033 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
68.033 [  OK  ] Started motd-news.timer - Message of the Day.
68.033 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
68.033 [  OK  ] Reached target timers.target - Timer Units.
68.033 [  OK  ] Reached target basic.target - Basic System.
68.055          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
68.075          Starting getty-static.service - geâ¦bus and logind are not available...
68.096          Starting systemd-user-sessions.service - Permit User Sessions...
68.137          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
68.158 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
68.220 [  OK  ] Started getty@tty1.service - Getty on tty1.
68.281 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
68.302 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
68.384 [  OK  ] Started getty@tty2.service - Getty on tty2.
68.405 [  OK  ] Started getty@tty3.service - Getty on tty3.
68.446 [  OK  ] Started getty@tty4.service - Getty on tty4.
68.446 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
68.466 [  OK  ] Started getty@tty5.service - Getty on tty5.
68.487 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
68.509 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
68.509 [  OK  ] Started getty@tty6.service - Getty on tty6.
68.530 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
68.550 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
68.550 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
68.571 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
68.612 [  OK  ] Reached target getty.target - Login Prompts.
68.612 [  OK  ] Reached target multi-user.target - Multi-User System.
68.612 [  OK  ] Reached target graphical.target - Graphical Interface.
68.633          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
68.674 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
