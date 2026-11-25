# tailts start epoch=1795480416.083
0.123 iPXE initialising devices...
0.739 
0.739 
0.739 
0.760 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.760 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.781 WRRUN-STUB
3.867 Configuring (net0 52:54:00:77:11:49)...... ok
3.867 tftp://10.0.2.2/autoexec.ipxe... ok
3.867 WRRUN-BEGIN row=B2
3.908 Waiting for link-up on net1... ok
3.908 WRRUN-NET-OK
3.908 WRRUN-SAN-START sanboot
3.928 rbd: stack high-water 2096 of 16384 bytes (14288 left)
3.990 rbd: stack high-water 2696 of 16384 bytes (13688 left)
3.990 rbd: stack high-water 2980 of 16384 bytes (13404 left)
4.093 rbd: stack high-water 3232 of 16384 bytes (13152 left)
4.114 Registered SAN device 0x80
4.114 Booting from SAN device 0x80
4.114 rbd: stack high-water 3380 of 16384 bytes (13004 left)
4.586 rbd: stack high-water 4048 of 16384 bytes (12336 left)
5.368 GNU GRUB  version 2.14
5.368 
5.388 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.388       Press enter to boot the selected OS, `e' to edit the commands       
16.508       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
16.549 Starting systemd-udevd version 255.4-1ubuntu8.19
17.100 Begin: Loading essential drivers ... done.
17.100 Begin: Running /scripts/init-premount ... done.
17.136 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
17.136 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
17.402 RBFT-HOOK table found by source scan
17.423 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
17.423 RBFT-HOOK nic: eth1 address 10.77.0.73/24
17.423 RBFT-HOOK table check (source scan):
17.709 RBFT INFO source: scan: found at physical address 0x9e140 (1 valid copy/copies)
17.730 RBFT PASS signature: rBFT
17.730 RBFT PASS length: 234 bytes
17.730 RBFT PASS acpi_revision: 1
17.730 RBFT PASS checksum: all 234 bytes sum to 0
17.730 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
17.730 RBFT PASS magic: WRBT
17.730 RBFT PASS version: 1
17.730 RBFT PASS header_len: 116
17.730 RBFT PASS reserved: all reserved bytes are zero
17.730 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.730 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.730 RBFT PASS namespace: absent (as in version 1)
17.730 RBFT PASS rules: every rule of the field table holds
17.730 RBFT PASS entity: wrtest-p2-b2
17.730 RBFT PASS pool: winrbd
17.730 RBFT PASS image: wrtest-p2-b2
17.730 RBFT PASS image_id: 3fba3d9c1c3f
17.730 RBFT PASS snapshot: absent, as expected
17.730 RBFT PASS auth: cephx
17.730 RBFT PASS msgr_mode: crc
17.730 RBFT PASS flags: key,static (0x6)
17.750 RBFT PASS flag_readonly: clear
17.750 RBFT PASS flag_key: set
17.750 RBFT PASS flag_nic_static: set
17.750 RBFT PASS flag_vlan: clear
17.750 RBFT PASS flag_fsid: clear
17.750 RBFT PASS flag_secure_required: clear
17.750 RBFT PASS key_type: aes
17.750 RBFT PASS key_len: 16
17.750 RBFT INFO key: present in the table (aes, 16 bytes), not printed
17.750 RBFT PASS mon_count: 1
17.750 RBFT PASS mon0: 10.77.0.10:3300
17.750 RBFT PASS fsid: none, as expected
17.750 RBFT PASS nic_mac: 52:54:00:77:12:c9
17.750 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
17.750 RBFT PASS nic_vlan: 0
17.750 RBFT PASS nic_mtu: 1500
17.750 RBFT PASS nic_family: 4
17.750 RBFT PASS nic_ip: 10.77.0.73
17.750 RBFT PASS nic_prefix: 24
17.750 RBFT PASS nic_gateway: zero, as expected
17.750 RBFT PASS nic_dns: zero, as expected
17.750 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 bb 46 45 4e 53 59 53
17.771 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
17.771 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
17.771 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
17.771 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
17.771 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
17.771 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.771 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.771 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
17.771 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
17.771 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
17.771 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 66 62 61 33 64 39
17.771 RBFT DUMP 00c0: 63 31 63 33 66 00 04 00 e4 0c 0a 4d 00 0a 00 00
17.771 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
17.771 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
17.792 RBFT-RESULT PASS pass=40 fail=0 skip=0
17.792 WRBOOT-TABLE PASS
17.833 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
17.894 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
17.894 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
17.894 done.
17.915 Begin: Running /scripts/local-premount ... done.
48.011 Warning: fsck not present, so skipping root file system
48.052 done.
48.052 Begin: Running /scripts/local-bottom ... done.
48.073 Begin: Running /scripts/init-bottom ... done.
49.220 
49.220 Welcome to Ubuntu 24.04 LTS!
49.220 
50.244 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
50.244 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
50.244 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
50.244 [  OK  ] Created slice user.slice - User and Session Slice.
50.244 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
50.264 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
50.264 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
50.264          Expecting device dev-ttyS0.device - /dev/ttyS0...
50.264 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
50.264 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
50.264 [  OK  ] Reached target paths.target - Path Units.
50.285 [  OK  ] Reached target remote-fs.target - Remote File Systems.
50.285 [  OK  ] Reached target slices.target - Slice Units.
50.285 [  OK  ] Reached target swap.target - Swaps.
50.285 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
50.285 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
50.285 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
50.285 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
50.306 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
50.306 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
50.327          Mounting dev-hugepages.mount - Huge Pages File System...
50.327          Mounting dev-mqueue.mount - POSIX Message Queue File System...
50.347          Mounting sys-kernel-debug.mount - Kernel Debug File System...
50.368          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
50.368          Starting systemd-journald.service - Journal Service...
50.388          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
50.388          Starting modprobe@configfs.service - Load Kernel Module configfs...
50.409          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
50.430          Starting modprobe@drm.service - Load Kernel Module drm...
50.450          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
50.450          Starting modprobe@fuse.service - Load Kernel Module fuse...
50.471          Starting modprobe@loop.service - Load Kernel Module loop...
50.492          Starting systemd-modules-load.service - Load Kernel Modules...
50.512          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
50.533          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
50.533 [  OK  ] Started systemd-journald.service - Journal Service.
50.554 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
50.554 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
50.554 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
50.554 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
50.574 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
50.595 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
50.595 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
50.616 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
50.616 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
50.636 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
50.636 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
50.657 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
50.657 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
50.698          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
50.698          Mounting sys-kernel-config.mount - Kernel Configuration File System...
50.719          Starting systemd-random-seed.service - Load/Save OS Random Seed...
50.740          Starting systemd-sysctl.service - Apply Kernel Variables...
50.760          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
50.760 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
50.781 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
50.781 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
50.863 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
50.863 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
50.905 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
50.925          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
50.967 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
50.967 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
50.987          Mounting tmp.mount - /tmp...
50.987          Mounting var-cache.mount - /var/cache...
51.008          Mounting var-log.mount - /var/log...
51.008          Mounting var-tmp.mount - /var/tmp...
51.029          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
51.029 [  OK  ] Mounted tmp.mount - /tmp.
51.029 [  OK  ] Mounted var-cache.mount - /var/cache.
51.029 [  OK  ] Mounted var-log.mount - /var/log.
51.029 [  OK  ] Mounted var-tmp.mount - /var/tmp.
51.050 [  OK  ] Reached target local-fs.target - Local File Systems.
51.050 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
51.050 [  OK  ] Reached target sockets.target - Socket Units.
51.071          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
51.113 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
51.134          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
51.195 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
51.216          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
51.236 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
51.380 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
51.380 [  OK  ] Reached target sysinit.target - System Initialization.
51.401 [  OK  ] Started apt-daily.timer - Daily apt download activities.
51.401 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
51.401 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
51.401 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
51.422 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
51.422 [  OK  ] Started motd-news.timer - Message of the Day.
51.422 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
51.422 [  OK  ] Reached target timers.target - Timer Units.
51.422 [  OK  ] Reached target basic.target - Basic System.
51.443          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
51.463          Starting getty-static.service - geâ¦bus and logind are not available...
51.463          Starting systemd-user-sessions.service - Permit User Sessions...
51.505          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
51.526 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
51.567 [  OK  ] Started getty@tty1.service - Getty on tty1.
51.629 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
51.629 [  OK  ] Started getty@tty2.service - Getty on tty2.
51.629 WRBOOT-EDD int13_dev81 mbr_signature=-
51.671 [  OK  ] Started getty@tty3.service - Getty on tty3.
51.713 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
51.733 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
51.754 [  OK  ] Started getty@tty4.service - Getty on tty4.
51.775 [  OK  ] Started getty@tty5.service - Getty on tty5.
51.795 [  OK  ] Started getty@tty6.service - Getty on tty6.
51.816 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
51.816 [  OK  ] Reached target getty.target - Login Prompts.
52.001 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
52.022 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
52.022 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
52.043 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
52.043 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
52.064 [  OK  ] Reached target multi-user.target - Multi-User System.
52.064 [  OK  ] Reached target graphical.target - Graphical Interface.
52.085          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
52.106 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
