# tailts start epoch=1795465586.762
8.092 iPXE initialising devices...
8.318 
8.338 
8.359 
8.379 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.421 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.442 WRRUN-STUB
11.585 Configuring (net0 52:54:00:77:12:d6)...... ok
11.627 tftp://10.77.0.10/autoexec.ipxe... ok
11.647 WRRUN-BEGIN row=B1
11.710 Waiting for link-up on net0... ok
11.730 WRRUN-NET-OK
11.751 WRRUN-SAN-START sanboot
12.206 Registered SAN device 0x80
12.227 Booting from SAN device 0x80
13.708 GNU GRUB  version 2.14
13.708 
13.728 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.749       Press enter to boot the selected OS, `e' to edit the commands       
22.058       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
22.099 Starting systemd-udevd version 255.4-1ubuntu8.19
22.671 Begin: Loading essential drivers ... done.
22.671 Begin: Running /scripts/init-premount ... done.
22.712 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
22.712 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
23.000 RBFT-HOOK table found by source scan
23.000 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:d6
23.000 RBFT-HOOK nic: eth0 address 10.77.0.86/24
23.000 RBFT-HOOK table check (source scan):
23.309 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
23.309 RBFT PASS signature: rBFT
23.309 RBFT PASS length: 234 bytes
23.309 RBFT PASS acpi_revision: 1
23.309 RBFT PASS checksum: all 234 bytes sum to 0
23.309 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
23.309 RBFT PASS magic: WRBT
23.309 RBFT PASS version: 1
23.309 RBFT PASS header_len: 116
23.330 RBFT PASS reserved: all reserved bytes are zero
23.330 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
23.330 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
23.330 RBFT PASS namespace: absent (as in version 1)
23.330 RBFT PASS rules: every rule of the field table holds
23.330 RBFT PASS entity: wrtest-p2-b1
23.330 RBFT PASS pool: winrbd
23.330 RBFT PASS image: wrtest-p2-b1
23.330 RBFT PASS image_id: 38d9a2e0bcec
23.330 RBFT PASS snapshot: absent, as expected
23.330 RBFT PASS auth: cephx
23.330 RBFT PASS msgr_mode: crc
23.330 RBFT PASS flags: key,static (0x6)
23.330 RBFT PASS flag_readonly: clear
23.351 RBFT PASS flag_key: set
23.351 RBFT PASS flag_nic_static: set
23.351 RBFT PASS flag_vlan: clear
23.351 RBFT PASS flag_fsid: clear
23.351 RBFT PASS flag_secure_required: clear
23.351 RBFT PASS key_type: aes
23.351 RBFT PASS key_len: 16
23.351 RBFT INFO key: present in the table (aes, 16 bytes), not printed
23.351 RBFT PASS mon_count: 1
23.351 RBFT PASS mon0: 10.77.0.10:3300
23.351 RBFT PASS fsid: none, as expected
23.351 RBFT PASS nic_mac: 52:54:00:77:12:d6
23.351 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d6 exists in this guest
23.351 RBFT PASS nic_vlan: 0
23.351 RBFT PASS nic_mtu: 1500
23.351 RBFT PASS nic_family: 4
23.351 RBFT PASS nic_ip: 10.77.0.86
23.373 RBFT PASS nic_prefix: 24
23.373 RBFT PASS nic_gateway: zero, as expected
23.373 RBFT PASS nic_dns: zero, as expected
23.373 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 19 46 45 4e 53 59 53
23.373 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
23.373 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
23.373 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
23.373 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d6 00 00
23.373 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 56 00 00 00 00 00 00 00 00
23.373 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
23.394 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
23.394 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
23.394 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
23.394 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
23.394 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
23.394 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
23.394 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
23.394 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
23.394 RBFT-RESULT PASS pass=40 fail=0 skip=0
23.394 WRBOOT-TABLE PASS
23.475 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
23.537 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
23.537 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
23.537 done.
23.557 Begin: Running /scripts/local-premount ... done.
53.647 Warning: fsck not present, so skipping root file system
53.667 done.
53.688 Begin: Running /scripts/local-bottom ... done.
53.709 Begin: Running /scripts/init-bottom ... done.
54.856 
54.856 Welcome to Ubuntu 24.04 LTS!
54.856 
55.513 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
55.513 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
55.513 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
55.534 [  OK  ] Created slice user.slice - User and Session Slice.
55.534 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
55.534 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
55.534 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
55.534          Expecting device dev-ttyS0.device - /dev/ttyS0...
55.554 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
55.554 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
55.554 [  OK  ] Reached target paths.target - Path Units.
55.554 [  OK  ] Reached target remote-fs.target - Remote File Systems.
55.554 [  OK  ] Reached target slices.target - Slice Units.
55.554 [  OK  ] Reached target swap.target - Swaps.
55.554 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
55.575 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
55.575 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
55.575 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
55.575 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
55.575 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
55.596          Mounting dev-hugepages.mount - Huge Pages File System...
55.596          Mounting dev-mqueue.mount - POSIX Message Queue File System...
55.617          Mounting sys-kernel-debug.mount - Kernel Debug File System...
55.637          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
55.658          Starting systemd-journald.service - Journal Service...
55.658          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
55.679          Starting modprobe@configfs.service - Load Kernel Module configfs...
55.700          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
55.700          Starting modprobe@drm.service - Load Kernel Module drm...
55.721          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
55.721          Starting modprobe@fuse.service - Load Kernel Module fuse...
55.741          Starting modprobe@loop.service - Load Kernel Module loop...
55.762          Starting systemd-modules-load.service - Load Kernel Modules...
55.783          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
55.803          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
55.803 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
55.824 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
55.824 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
55.844 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
55.844 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
55.865 [  OK  ] Started systemd-journald.service - Journal Service.
55.886 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
55.886 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
55.906 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
55.927 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
55.927 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
55.927 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
55.947 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
55.947 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
55.989          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
56.010          Mounting sys-kernel-config.mount - Kernel Configuration File System...
56.031          Starting systemd-random-seed.service - Load/Save OS Random Seed...
56.072          Starting systemd-sysctl.service - Apply Kernel Variables...
56.072          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
56.092 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
56.092 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
56.113 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
56.154 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
56.154 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
56.215 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
56.235          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
56.276 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
56.276 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
56.276          Mounting tmp.mount - /tmp...
56.297          Mounting var-cache.mount - /var/cache...
56.318          Mounting var-log.mount - /var/log...
56.318          Mounting var-tmp.mount - /var/tmp...
56.338          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
56.338 [  OK  ] Mounted tmp.mount - /tmp.
56.338 [  OK  ] Mounted var-cache.mount - /var/cache.
56.338 [  OK  ] Mounted var-log.mount - /var/log.
56.338 [  OK  ] Mounted var-tmp.mount - /var/tmp.
56.359 [  OK  ] Reached target local-fs.target - Local File Systems.
56.380 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
56.380 [  OK  ] Reached target sockets.target - Socket Units.
56.401          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
56.442 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
56.442          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
56.504 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
56.525          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
56.546 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
56.546 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
56.567 [  OK  ] Reached target sysinit.target - System Initialization.
56.567 [  OK  ] Started apt-daily.timer - Daily apt download activities.
56.567 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
56.567 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
56.567 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
56.588 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
56.588 [  OK  ] Started motd-news.timer - Message of the Day.
56.588 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
56.588 [  OK  ] Reached target timers.target - Timer Units.
56.588 [  OK  ] Reached target basic.target - Basic System.
56.609          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
56.629          Starting getty-static.service - geâ¦bus and logind are not available...
56.650          Starting systemd-user-sessions.service - Permit User Sessions...
56.671          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
56.753 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
56.774 [  OK  ] Started getty@tty1.service - Getty on tty1.
56.794 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
56.815 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
56.836 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
56.857 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
56.960 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
56.960 WRBOOT-NET eth0 mac=52:54:00:77:12:d6 10.77.0.86/24 fe80::5054:ff:fe77:12d6/64 
56.980 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
56.980 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
57.022 [  OK  ] Started getty@tty2.service - Getty on tty2.
57.043 [  OK  ] Started getty@tty3.service - Getty on tty3.
57.064 [  OK  ] Started getty@tty4.service - Getty on tty4.
57.084 [  OK  ] Started getty@tty5.service - Getty on tty5.
57.105 [  OK  ] Started getty@tty6.service - Getty on tty6.
57.105 [  OK  ] Reached target getty.target - Login Prompts.
57.105 [  OK  ] Reached target multi-user.target - Multi-User System.
57.126 [  OK  ] Reached target graphical.target - Graphical Interface.
57.147          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
57.188 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
