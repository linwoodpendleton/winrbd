# tailts start epoch=1795464658.102
0.021 iPXE initialising devices...
0.369 
0.369 
0.369 
0.411 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.452 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.452 WRRUN-STUB
3.630 Configuring (net0 52:54:00:77:11:4a)...... ok
3.651 tftp://10.0.2.2/autoexec.ipxe... ok
3.651 WRRUN-BEGIN row=B3
3.692 Waiting for link-up on net1... ok
3.692 WRRUN-NET-OK
3.692 WRRUN-SAN-START sanboot
3.960 Registered SAN device 0x80
3.960 Booting from SAN device 0x80
6.481 GNU GRUB  version 2.14
6.481 
6.502 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
6.502       Press enter to boot the selected OS, `e' to edit the commands       
15.503       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
15.544 Starting systemd-udevd version 255.4-1ubuntu8.19
16.345 Begin: Loading essential drivers ... done.
16.345 Begin: Running /scripts/init-premount ... done.
16.385 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
16.385 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
16.674 RBFT-HOOK table found by source scan
16.674 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
16.674 RBFT-HOOK nic: eth1 address 10.77.0.74/24
16.674 RBFT-HOOK table check (source scan):
16.981 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
16.981 RBFT PASS signature: rBFT
16.981 RBFT PASS length: 234 bytes
16.981 RBFT PASS acpi_revision: 1
16.981 RBFT PASS checksum: all 234 bytes sum to 0
16.981 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
16.981 RBFT PASS magic: WRBT
17.002 RBFT PASS version: 1
17.002 RBFT PASS header_len: 116
17.002 RBFT PASS reserved: all reserved bytes are zero
17.002 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.002 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.002 RBFT PASS namespace: absent (as in version 1)
17.002 RBFT PASS rules: every rule of the field table holds
17.002 RBFT PASS entity: wrtest-p2-b3
17.002 RBFT PASS pool: winrbd
17.002 RBFT PASS image: wrtest-p2-b3
17.002 RBFT PASS image_id: 39648e0b332d
17.002 RBFT PASS snapshot: absent, as expected
17.002 RBFT PASS auth: cephx
17.002 RBFT PASS msgr_mode: crc
17.002 RBFT PASS flags: key,static (0x6)
17.023 RBFT PASS flag_readonly: clear
17.023 RBFT PASS flag_key: set
17.023 RBFT PASS flag_nic_static: set
17.023 RBFT PASS flag_vlan: clear
17.023 RBFT PASS flag_fsid: clear
17.023 RBFT PASS flag_secure_required: clear
17.023 RBFT PASS key_type: aes
17.023 RBFT PASS key_len: 16
17.023 RBFT INFO key: present in the table (aes, 16 bytes), not printed
17.023 RBFT PASS mon_count: 1
17.023 RBFT PASS mon0: 10.77.0.10:3300
17.023 RBFT PASS fsid: none, as expected
17.023 RBFT PASS nic_mac: 52:54:00:77:12:ca
17.044 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
17.044 RBFT PASS nic_vlan: 0
17.044 RBFT PASS nic_mtu: 1500
17.044 RBFT PASS nic_family: 4
17.044 RBFT PASS nic_ip: 10.77.0.74
17.044 RBFT PASS nic_prefix: 24
17.044 RBFT PASS nic_gateway: zero, as expected
17.044 RBFT PASS nic_dns: zero, as expected
17.044 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
17.044 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
17.044 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
17.044 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
17.065 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
17.065 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
17.065 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.065 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.065 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
17.065 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
17.065 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
17.065 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
17.065 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
17.065 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
17.065 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
17.086 RBFT-RESULT PASS pass=40 fail=0 skip=0
17.086 WRBOOT-TABLE PASS
17.315 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
17.397 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
17.397 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
17.397 done.
17.418 Begin: Running /scripts/local-premount ... done.
86.034 Warning: fsck not present, so skipping root file system
86.056 done.
86.077 Begin: Running /scripts/local-bottom ... done.
86.118 Begin: Running /scripts/init-bottom ... done.
91.025 
91.025 Welcome to Ubuntu 24.04 LTS!
91.025 
94.478 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
94.500 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
94.500 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
94.500 [  OK  ] Created slice user.slice - User and Session Slice.
94.521 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
94.521 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
94.521 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
94.521          Expecting device dev-ttyS0.device - /dev/ttyS0...
94.521 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
94.541 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
94.541 [  OK  ] Reached target paths.target - Path Units.
94.541 [  OK  ] Reached target remote-fs.target - Remote File Systems.
94.541 [  OK  ] Reached target slices.target - Slice Units.
94.541 [  OK  ] Reached target swap.target - Swaps.
94.541 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
94.541 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
94.562 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
94.562 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
94.562 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
94.562 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
94.583          Mounting dev-hugepages.mount - Huge Pages File System...
94.728          Mounting dev-mqueue.mount - POSIX Message Queue File System...
94.728          Mounting sys-kernel-debug.mount - Kernel Debug File System...
94.749          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
94.770          Starting systemd-journald.service - Journal Service...
94.790          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
94.811          Starting modprobe@configfs.service - Load Kernel Module configfs...
94.832          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
94.853          Starting modprobe@drm.service - Load Kernel Module drm...
94.853          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
94.873          Starting modprobe@fuse.service - Load Kernel Module fuse...
94.894          Starting modprobe@loop.service - Load Kernel Module loop...
94.915          Starting systemd-modules-load.service - Load Kernel Modules...
94.935          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
94.935          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
94.956 [  OK  ] Started systemd-journald.service - Journal Service.
94.956 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
94.956 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
94.977 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
94.977 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
94.998 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
94.998 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
95.018 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
95.018 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
95.018 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
95.039 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
95.060 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
95.060 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
95.122          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
95.143          Mounting sys-kernel-config.mount - Kernel Configuration File System...
95.143          Starting systemd-sysctl.service - Apply Kernel Variables...
95.163          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
95.184 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
95.184 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
95.184 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
95.521          Starting systemd-random-seed.service - Load/Save OS Random Seed...
95.542 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
95.562 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
95.686 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
95.706          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
95.727 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
95.727 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
95.727          Mounting tmp.mount - /tmp...
95.748          Mounting var-cache.mount - /var/cache...
95.768          Mounting var-log.mount - /var/log...
95.789          Mounting var-tmp.mount - /var/tmp...
95.789          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
95.810 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
95.810 [  OK  ] Mounted tmp.mount - /tmp.
95.810 [  OK  ] Mounted var-cache.mount - /var/cache.
95.830 [  OK  ] Mounted var-log.mount - /var/log.
95.830 [  OK  ] Mounted var-tmp.mount - /var/tmp.
95.830 [  OK  ] Reached target local-fs.target - Local File Systems.
95.851 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
95.851 [  OK  ] Reached target sockets.target - Socket Units.
95.872          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
95.913 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
95.934          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
95.976 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
95.996          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
96.037 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
96.079 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
96.100 [  OK  ] Reached target sysinit.target - System Initialization.
96.100 [  OK  ] Started apt-daily.timer - Daily apt download activities.
96.100 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
96.100 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
96.121 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
96.121 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
96.121 [  OK  ] Started motd-news.timer - Message of the Day.
96.121 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
96.121 [  OK  ] Reached target timers.target - Timer Units.
96.141 [  OK  ] Reached target basic.target - Basic System.
96.141          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
96.162          Starting getty-static.service - geâ¦bus and logind are not available...
96.183          Starting systemd-user-sessions.service - Permit User Sessions...
96.584          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
96.736 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
96.799 [  OK  ] Started getty@tty1.service - Getty on tty1.
96.841 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
96.841 [  OK  ] Started getty@tty2.service - Getty on tty2.
96.965 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
97.048 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
97.048 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
97.048 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
97.069 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
97.069 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
97.090 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
97.193 [  OK  ] Started getty@tty3.service - Getty on tty3.
