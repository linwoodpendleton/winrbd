# tailts start epoch=1795465335.394
8.076 iPXE initialising devices...
8.096 
8.117 
8.137 
8.179 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.200 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.220 WRRUN-STUB
11.487 Configuring (net0 52:54:00:77:12:c7)...... ok
11.529 tftp://10.77.0.10/autoexec.ipxe... ok
11.549 WRRUN-BEGIN row=B1
11.590 Waiting for link-up on net0... ok
11.611 WRRUN-NET-OK
11.652 WRRUN-SAN-START sanboot
12.020 Registered SAN device 0x80
12.041 Booting from SAN device 0x80
13.375 GNU GRUB  version 2.14
13.375 
13.396 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.416       Press enter to boot the selected OS, `e' to edit the commands       
51.330       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
51.433 Starting systemd-udevd version 255.4-1ubuntu8.19
52.171 Begin: Loading essential drivers ... done.
52.171 Begin: Running /scripts/init-premount ... done.
52.212 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
52.212 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
52.705 RBFT-HOOK table found by source scan
52.705 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
52.705 RBFT-HOOK nic: eth0 address 10.77.0.71/24
52.705 RBFT-HOOK table check (source scan):
52.971 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
52.971 RBFT PASS signature: rBFT
52.971 RBFT PASS length: 234 bytes
52.971 RBFT PASS acpi_revision: 1
52.971 RBFT PASS checksum: all 234 bytes sum to 0
52.971 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
52.971 RBFT PASS magic: WRBT
52.971 RBFT PASS version: 1
52.971 RBFT PASS header_len: 116
52.971 RBFT PASS reserved: all reserved bytes are zero
52.971 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
52.971 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
52.992 RBFT PASS namespace: absent (as in version 1)
52.992 RBFT PASS rules: every rule of the field table holds
52.992 RBFT PASS entity: wrtest-p2-b1
52.992 RBFT PASS pool: winrbd
52.992 RBFT PASS image: wrtest-p2-b1
52.992 RBFT PASS image_id: 38d9a2e0bcec
52.992 RBFT PASS snapshot: absent, as expected
52.992 RBFT PASS auth: cephx
52.992 RBFT PASS msgr_mode: crc
52.992 RBFT PASS flags: key,static (0x6)
52.992 RBFT PASS flag_readonly: clear
52.992 RBFT PASS flag_key: set
52.992 RBFT PASS flag_nic_static: set
52.992 RBFT PASS flag_vlan: clear
52.992 RBFT PASS flag_fsid: clear
52.992 RBFT PASS flag_secure_required: clear
52.992 RBFT PASS key_type: aes
52.992 RBFT PASS key_len: 16
53.013 RBFT INFO key: present in the table (aes, 16 bytes), not printed
53.013 RBFT PASS mon_count: 1
53.013 RBFT PASS mon0: 10.77.0.10:3300
53.013 RBFT PASS fsid: none, as expected
53.013 RBFT PASS nic_mac: 52:54:00:77:12:c7
53.013 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
53.013 RBFT PASS nic_vlan: 0
53.013 RBFT PASS nic_mtu: 1500
53.013 RBFT PASS nic_family: 4
53.013 RBFT PASS nic_ip: 10.77.0.71
53.013 RBFT PASS nic_prefix: 24
53.013 RBFT PASS nic_gateway: zero, as expected
53.013 RBFT PASS nic_dns: zero, as expected
53.013 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
53.013 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
53.013 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
53.033 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
53.033 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
53.033 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
53.033 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
53.033 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
53.033 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
53.033 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
53.033 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
53.033 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
53.033 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
53.054 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
53.054 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
53.054 RBFT-RESULT PASS pass=40 fail=0 skip=0
53.054 WRBOOT-TABLE PASS
53.115 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
53.197 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
53.197 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
53.197 done.
53.197 Begin: Running /scripts/local-premount ... done.
83.546 Warning: fsck not present, so skipping root file system
83.567 done.
83.587 Begin: Running /scripts/local-bottom ... done.
83.674 Begin: Running /scripts/init-bottom ... done.
85.969 
85.969 Welcome to Ubuntu 24.04 LTS!
85.969 
88.796 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
88.796 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
88.796 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
88.818 [  OK  ] Created slice user.slice - User and Session Slice.
88.838 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
88.838 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
88.859 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
88.859          Expecting device dev-ttyS0.device - /dev/ttyS0...
88.859 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
88.859 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
88.880 [  OK  ] Reached target paths.target - Path Units.
88.880 [  OK  ] Reached target remote-fs.target - Remote File Systems.
88.880 [  OK  ] Reached target slices.target - Slice Units.
88.880 [  OK  ] Reached target swap.target - Swaps.
88.880 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
88.880 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
88.901 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
88.901 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
88.901 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
88.921 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
88.983          Mounting dev-hugepages.mount - Huge Pages File System...
88.983          Mounting dev-mqueue.mount - POSIX Message Queue File System...
89.004          Mounting sys-kernel-debug.mount - Kernel Debug File System...
89.004          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
89.025          Starting systemd-journald.service - Journal Service...
89.025          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
89.045          Starting modprobe@configfs.service - Load Kernel Module configfs...
89.066          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
89.087          Starting modprobe@drm.service - Load Kernel Module drm...
89.108          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
89.108          Starting modprobe@fuse.service - Load Kernel Module fuse...
89.128          Starting modprobe@loop.service - Load Kernel Module loop...
89.170          Starting systemd-modules-load.service - Load Kernel Modules...
89.170          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
89.190          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
89.190 [  OK  ] Started systemd-journald.service - Journal Service.
89.211 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
89.211 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
89.211 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
89.211 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
89.231 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
89.252 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
90.145 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
90.207 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
90.249 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
91.020 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
91.104 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
91.187 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
91.784          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
91.846          Mounting sys-kernel-config.mount - Kernel Configuration File System...
91.908          Starting systemd-sysctl.service - Apply Kernel Variables...
91.992          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
91.992 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
92.013 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
92.013 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
92.055          Starting systemd-random-seed.service - Load/Save OS Random Seed...
92.096 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
92.117 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
92.158 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
92.178          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
92.199 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
92.199 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
92.220 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
92.220          Mounting tmp.mount - /tmp...
92.240          Mounting var-cache.mount - /var/cache...
92.756          Mounting var-log.mount - /var/log...
92.777          Mounting var-tmp.mount - /var/tmp...
92.777          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
92.798 [  OK  ] Mounted tmp.mount - /tmp.
92.798 [  OK  ] Mounted var-cache.mount - /var/cache.
92.798 [  OK  ] Mounted var-log.mount - /var/log.
92.819 [  OK  ] Mounted var-tmp.mount - /var/tmp.
92.819 [  OK  ] Reached target local-fs.target - Local File Systems.
92.840 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
92.860 [  OK  ] Reached target sockets.target - Socket Units.
92.966          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
93.007 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
93.049          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
93.111 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
93.132          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
93.173 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
93.173 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
93.194 [  OK  ] Reached target sysinit.target - System Initialization.
93.194 [  OK  ] Started apt-daily.timer - Daily apt download activities.
93.215 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
93.215 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
93.215 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
93.236 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
93.236 [  OK  ] Started motd-news.timer - Message of the Day.
93.236 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
93.236 [  OK  ] Reached target timers.target - Timer Units.
93.236 [  OK  ] Reached target basic.target - Basic System.
93.698          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
94.860          Starting getty-static.service - geâ¦bus and logind are not available...
95.090          Starting systemd-user-sessions.service - Permit User Sessions...
95.195          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
96.164 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
97.032 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
97.239 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
97.239 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
97.940 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
97.940 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
97.940 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
97.960 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
97.960 [  OK  ] Started getty@tty1.service - Getty on tty1.
98.002 [  OK  ] Started getty@tty2.service - Getty on tty2.
98.002 [  OK  ] Started getty@tty3.service - Getty on tty3.
98.043 [  OK  ] Started getty@tty4.service - Getty on tty4.
98.064 [  OK  ] Started getty@tty5.service - Getty on tty5.
98.064 [  OK  ] Started getty@tty6.service - Getty on tty6.
98.105 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
98.105 [  OK  ] Reached target getty.target - Login Prompts.
98.105 [  OK  ] Reached target multi-user.target - Multi-User System.
98.105 [  OK  ] Reached target graphical.target - Graphical Interface.
98.126          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
98.189 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
