# tailts start epoch=1795468718.985
7.778 iPXE initialising devices...
7.799 
7.819 
7.819 
7.840 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.881 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.902 WRRUN-STUB
11.029 Configuring (net0 52:54:00:77:12:c7)...... ok
11.070 tftp://10.77.0.10/autoexec.ipxe... ok
11.091 WRRUN-BEGIN row=B1
11.153 Waiting for link-up on net0... ok
11.173 WRRUN-NET-OK
11.194 WRRUN-SAN-START sanboot
11.521 Registered SAN device 0x80
11.542 Booting from SAN device 0x80
13.136 GNU GRUB  version 2.14
13.136 
13.158 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.158       Press enter to boot the selected OS, `e' to edit the commands       
24.933       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
24.954 Starting systemd-udevd version 255.4-1ubuntu8.19
25.546 Begin: Loading essential drivers ... done.
25.546 Begin: Running /scripts/init-premount ... done.
25.587 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
25.587 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
25.874 RBFT-HOOK table found by source scan
25.874 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
25.874 RBFT-HOOK nic: eth0 address 10.77.0.71/24
25.874 RBFT-HOOK table check (source scan):
26.160 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
26.160 RBFT PASS signature: rBFT
26.160 RBFT PASS length: 234 bytes
26.181 RBFT PASS acpi_revision: 1
26.181 RBFT PASS checksum: all 234 bytes sum to 0
26.181 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
26.181 RBFT PASS magic: WRBT
26.181 RBFT PASS version: 1
26.181 RBFT PASS header_len: 116
26.181 RBFT PASS reserved: all reserved bytes are zero
26.181 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
26.181 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
26.181 RBFT PASS namespace: absent (as in version 1)
26.181 RBFT PASS rules: every rule of the field table holds
26.181 RBFT PASS entity: wrtest-p2-b1
26.181 RBFT PASS pool: winrbd
26.181 RBFT PASS image: wrtest-p2-b1
26.202 RBFT PASS image_id: 38d9a2e0bcec
26.202 RBFT PASS snapshot: absent, as expected
26.202 RBFT PASS auth: cephx
26.202 RBFT PASS msgr_mode: crc
26.202 RBFT PASS flags: key,static (0x6)
26.202 RBFT PASS flag_readonly: clear
26.202 RBFT PASS flag_key: set
26.202 RBFT PASS flag_nic_static: set
26.202 RBFT PASS flag_vlan: clear
26.202 RBFT PASS flag_fsid: clear
26.202 RBFT PASS flag_secure_required: clear
26.202 RBFT PASS key_type: aes
26.202 RBFT PASS key_len: 16
26.202 RBFT INFO key: present in the table (aes, 16 bytes), not printed
26.202 RBFT PASS mon_count: 1
26.202 RBFT PASS mon0: 10.77.0.10:3300
26.202 RBFT PASS fsid: none, as expected
26.222 RBFT PASS nic_mac: 52:54:00:77:12:c7
26.222 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
26.222 RBFT PASS nic_vlan: 0
26.222 RBFT PASS nic_mtu: 1500
26.222 RBFT PASS nic_family: 4
26.222 RBFT PASS nic_ip: 10.77.0.71
26.222 RBFT PASS nic_prefix: 24
26.222 RBFT PASS nic_gateway: zero, as expected
26.222 RBFT PASS nic_dns: zero, as expected
26.222 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
26.222 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
26.222 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
26.222 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
26.243 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
26.243 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
26.243 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.243 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.243 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
26.243 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
26.243 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
26.243 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
26.243 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
26.243 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
26.264 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
26.264 RBFT-RESULT PASS pass=40 fail=0 skip=0
26.264 WRBOOT-TABLE PASS
26.325 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
26.407 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
26.407 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
26.407 done.
26.407 Begin: Running /scripts/local-premount ... done.
56.503 Warning: fsck not present, so skipping root file system
56.524 done.
56.544 Begin: Running /scripts/local-bottom ... done.
56.565 Begin: Running /scripts/init-bottom ... done.
58.543 
58.543 Welcome to Ubuntu 24.04 LTS!
58.543 
59.521 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
59.521 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
59.521 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
59.521 [  OK  ] Created slice user.slice - User and Session Slice.
59.521 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
59.542 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
59.542 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
59.542          Expecting device dev-ttyS0.device - /dev/ttyS0...
59.542 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
59.542 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
59.542 [  OK  ] Reached target paths.target - Path Units.
59.542 [  OK  ] Reached target remote-fs.target - Remote File Systems.
59.542 [  OK  ] Reached target slices.target - Slice Units.
59.563 [  OK  ] Reached target swap.target - Swaps.
59.563 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
59.563 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
59.563 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
59.563 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
59.584 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
59.584 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
59.604          Mounting dev-hugepages.mount - Huge Pages File System...
59.604          Mounting dev-mqueue.mount - POSIX Message Queue File System...
59.604          Mounting sys-kernel-debug.mount - Kernel Debug File System...
59.625          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
59.645          Starting systemd-journald.service - Journal Service...
59.666          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
59.666          Starting modprobe@configfs.service - Load Kernel Module configfs...
59.686          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
59.686          Starting modprobe@drm.service - Load Kernel Module drm...
59.707          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
59.728          Starting modprobe@fuse.service - Load Kernel Module fuse...
59.749          Starting modprobe@loop.service - Load Kernel Module loop...
59.770          Starting systemd-modules-load.service - Load Kernel Modules...
59.790          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
59.790          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
59.811 [  OK  ] Started systemd-journald.service - Journal Service.
59.811 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
59.811 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
59.811 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
59.832 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
59.832 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
59.832 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
59.832 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
59.832 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
59.852 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
59.852 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
59.852 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
59.873 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
59.893          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
59.893          Mounting sys-kernel-config.mount - Kernel Configuration File System...
59.914          Starting systemd-sysctl.service - Apply Kernel Variables...
59.914          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
59.934 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
59.934 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
59.934 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
59.975          Starting systemd-random-seed.service - Load/Save OS Random Seed...
60.037 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
60.058 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
60.119 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
60.140          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
60.160 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
60.160 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
60.181          Mounting tmp.mount - /tmp...
60.181          Mounting var-cache.mount - /var/cache...
60.202          Mounting var-log.mount - /var/log...
60.222          Mounting var-tmp.mount - /var/tmp...
60.222          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
60.222 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
60.243 [  OK  ] Mounted tmp.mount - /tmp.
60.243 [  OK  ] Mounted var-cache.mount - /var/cache.
60.243 [  OK  ] Mounted var-log.mount - /var/log.
60.243 [  OK  ] Mounted var-tmp.mount - /var/tmp.
60.264 [  OK  ] Reached target local-fs.target - Local File Systems.
60.264 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
60.264 [  OK  ] Reached target sockets.target - Socket Units.
60.284          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
60.325 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
60.325          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
60.387 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
60.408          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
60.429 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
60.531 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
60.531 [  OK  ] Reached target sysinit.target - System Initialization.
60.531 [  OK  ] Started apt-daily.timer - Daily apt download activities.
60.531 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
60.531 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
60.551 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
60.551 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
60.551 [  OK  ] Started motd-news.timer - Message of the Day.
60.551 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
60.572 [  OK  ] Reached target timers.target - Timer Units.
60.572 [  OK  ] Reached target basic.target - Basic System.
60.572          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
60.593          Starting getty-static.service - geâ¦bus and logind are not available...
60.613          Starting systemd-user-sessions.service - Permit User Sessions...
60.634          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
60.715 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
60.757 [  OK  ] Started getty@tty1.service - Getty on tty1.
60.777 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
60.798 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
60.839 [  OK  ] Started getty@tty2.service - Getty on tty2.
60.839 [  OK  ] Started getty@tty3.service - Getty on tty3.
60.860 [  OK  ] Started getty@tty4.service - Getty on tty4.
60.880 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
60.921 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
60.982 [  OK  ] Started getty@tty5.service - Getty on tty5.
61.003 [  OK  ] Started getty@tty6.service - Getty on tty6.
61.003 [  OK  ] Reached target getty.target - Login Prompts.
61.105 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
61.167 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
61.187 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
61.187 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
61.187 [  OK  ] Reached target multi-user.target - Multi-User System.
61.187 [  OK  ] Reached target graphical.target - Graphical Interface.
61.208          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
61.249 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
