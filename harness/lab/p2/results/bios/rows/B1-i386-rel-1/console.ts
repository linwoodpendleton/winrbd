# tailts start epoch=1795464240.701
7.791 iPXE initialising devices...
7.832 
7.853 
7.873 
7.894 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.914 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.935 WRRUN-STUB
11.344 Configuring (net0 52:54:00:77:12:c7)...... ok
11.364 tftp://10.77.0.10/autoexec.ipxe... ok
11.385 WRRUN-BEGIN row=B1
11.467 Waiting for link-up on net0... ok
11.467 WRRUN-NET-OK
11.487 WRRUN-SAN-START sanboot
14.342 Registered SAN device 0x80
14.362 Booting from SAN device 0x80
17.894 GNU GRUB  version 2.14
17.894 
17.914 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
17.935       Press enter to boot the selected OS, `e' to edit the commands       
29.537       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
29.578 Starting systemd-udevd version 255.4-1ubuntu8.19
30.149 Begin: Loading essential drivers ... done.
30.149 Begin: Running /scripts/init-premount ... done.
30.170 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
30.170 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
30.455 RBFT-HOOK table found by source scan
30.455 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
30.455 RBFT-HOOK nic: eth0 address 10.77.0.71/24
30.455 RBFT-HOOK table check (source scan):
30.699 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
30.720 RBFT PASS signature: rBFT
30.720 RBFT PASS length: 234 bytes
30.720 RBFT PASS acpi_revision: 1
30.720 RBFT PASS checksum: all 234 bytes sum to 0
30.720 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
30.720 RBFT PASS magic: WRBT
30.720 RBFT PASS version: 1
30.720 RBFT PASS header_len: 116
30.720 RBFT PASS reserved: all reserved bytes are zero
30.720 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
30.720 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
30.720 RBFT PASS namespace: absent (as in version 1)
30.720 RBFT PASS rules: every rule of the field table holds
30.720 RBFT PASS entity: wrtest-p2-b1
30.720 RBFT PASS pool: winrbd
30.720 RBFT PASS image: wrtest-p2-b1
30.740 RBFT PASS image_id: 38d9a2e0bcec
30.740 RBFT PASS snapshot: absent, as expected
30.740 RBFT PASS auth: cephx
30.740 RBFT PASS msgr_mode: crc
30.740 RBFT PASS flags: key,static (0x6)
30.740 RBFT PASS flag_readonly: clear
30.740 RBFT PASS flag_key: set
30.740 RBFT PASS flag_nic_static: set
30.740 RBFT PASS flag_vlan: clear
30.740 RBFT PASS flag_fsid: clear
30.740 RBFT PASS flag_secure_required: clear
30.740 RBFT PASS key_type: aes
30.740 RBFT PASS key_len: 16
30.740 RBFT INFO key: present in the table (aes, 16 bytes), not printed
30.740 RBFT PASS mon_count: 1
30.740 RBFT PASS mon0: 10.77.0.10:3300
30.740 RBFT PASS fsid: none, as expected
30.740 RBFT PASS nic_mac: 52:54:00:77:12:c7
30.740 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
30.761 RBFT PASS nic_vlan: 0
30.761 RBFT PASS nic_mtu: 1500
30.761 RBFT PASS nic_family: 4
30.761 RBFT PASS nic_ip: 10.77.0.71
30.761 RBFT PASS nic_prefix: 24
30.761 RBFT PASS nic_gateway: zero, as expected
30.761 RBFT PASS nic_dns: zero, as expected
30.761 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
30.761 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
30.761 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
30.761 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
30.761 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
30.761 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
30.761 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
30.781 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
30.781 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
30.781 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
30.781 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
30.781 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
30.781 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
30.781 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
30.781 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
30.781 RBFT-RESULT PASS pass=40 fail=0 skip=0
30.781 WRBOOT-TABLE PASS
30.843 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
30.925 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
30.925 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
30.925 done.
30.945 Begin: Running /scripts/local-premount ... done.
61.878 Warning: fsck not present, so skipping root file system
62.021 done.
62.309 Begin: Running /scripts/local-bottom ... done.
62.330 Begin: Running /scripts/init-bottom ... done.
64.926 
64.926 Welcome to Ubuntu 24.04 LTS!
64.926 
67.649 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
67.670 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
67.670 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
67.670 [  OK  ] Created slice user.slice - User and Session Slice.
67.691 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
67.691 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
67.712 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
67.712          Expecting device dev-ttyS0.device - /dev/ttyS0...
67.712 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
67.712 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
67.712 [  OK  ] Reached target paths.target - Path Units.
67.712 [  OK  ] Reached target remote-fs.target - Remote File Systems.
67.733 [  OK  ] Reached target slices.target - Slice Units.
67.733 [  OK  ] Reached target swap.target - Swaps.
67.733 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
67.733 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
67.733 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
67.733 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
67.754 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
67.754 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
67.774          Mounting dev-hugepages.mount - Huge Pages File System...
67.774          Mounting dev-mqueue.mount - POSIX Message Queue File System...
67.795          Mounting sys-kernel-debug.mount - Kernel Debug File System...
67.795          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
67.816          Starting systemd-journald.service - Journal Service...
67.836          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
67.836          Starting modprobe@configfs.service - Load Kernel Module configfs...
67.857          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
67.878          Starting modprobe@drm.service - Load Kernel Module drm...
67.878          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
67.898          Starting modprobe@fuse.service - Load Kernel Module fuse...
67.940          Starting modprobe@loop.service - Load Kernel Module loop...
67.961          Starting systemd-modules-load.service - Load Kernel Modules...
67.981          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
68.002          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
68.002 [  OK  ] Started systemd-journald.service - Journal Service.
68.002 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
68.002 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
68.002 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
68.023 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
68.023 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
68.023 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
68.044 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
68.044 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
68.044 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
68.064 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
68.064 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
68.064 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
68.313          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
68.313          Mounting sys-kernel-config.mount - Kernel Configuration File System...
68.333          Starting systemd-sysctl.service - Apply Kernel Variables...
68.333          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
68.333 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
68.354 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
68.580 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
68.621          Starting systemd-random-seed.service - Load/Save OS Random Seed...
68.621 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
68.663 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
68.704 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
68.704          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
68.724 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
68.745 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
68.745          Mounting tmp.mount - /tmp...
68.766          Mounting var-cache.mount - /var/cache...
68.786          Mounting var-log.mount - /var/log...
68.807          Mounting var-tmp.mount - /var/tmp...
68.807          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
68.807 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
68.807 [  OK  ] Mounted tmp.mount - /tmp.
68.828 [  OK  ] Mounted var-cache.mount - /var/cache.
68.828 [  OK  ] Mounted var-log.mount - /var/log.
68.828 [  OK  ] Mounted var-tmp.mount - /var/tmp.
68.828 [  OK  ] Reached target local-fs.target - Local File Systems.
68.849 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
68.849 [  OK  ] Reached target sockets.target - Socket Units.
68.869          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
68.910 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
68.910          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
68.972 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
68.972          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
69.013 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
69.434 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
69.434 [  OK  ] Reached target sysinit.target - System Initialization.
69.434 [  OK  ] Started apt-daily.timer - Daily apt download activities.
69.434 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
69.455 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
69.518 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
69.518 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
69.518 [  OK  ] Started motd-news.timer - Message of the Day.
69.518 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
69.518 [  OK  ] Reached target timers.target - Timer Units.
69.518 [  OK  ] Reached target basic.target - Basic System.
69.539          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
69.560          Starting getty-static.service - geâ¦bus and logind are not available...
69.580          Starting systemd-user-sessions.service - Permit User Sessions...
69.622          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
69.642 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
69.684 [  OK  ] Started getty@tty1.service - Getty on tty1.
69.745 [  OK  ] Started getty@tty2.service - Getty on tty2.
69.786 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
69.807 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
69.868 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
69.889 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
69.909 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
69.909 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
69.930 [  OK  ] Started getty@tty3.service - Getty on tty3.
69.950 [  OK  ] Started getty@tty4.service - Getty on tty4.
69.971 [  OK  ] Started getty@tty5.service - Getty on tty5.
69.991 [  OK  ] Started getty@tty6.service - Getty on tty6.
70.012 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
70.012 [  OK  ] Reached target getty.target - Login Prompts.
70.012 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
70.012 [  OK  ] Reached target multi-user.target - Multi-User System.
70.012 [  OK  ] Reached target graphical.target - Graphical Interface.
70.033          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
70.074 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
