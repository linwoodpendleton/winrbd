# tailts start epoch=1795465139.025
0.309 iPXE initialising devices...
0.391 
0.391 
0.391 
0.412 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.433 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.454 WRRUN-STUB
3.575 Configuring (net0 52:54:00:77:11:52)...... ok
3.617 tftp://10.0.2.2/autoexec.ipxe... ok
3.638 WRRUN-BEGIN row=B3
3.823 Waiting for link-up on net1... ok
3.906 WRRUN-NET-OK
3.948 WRRUN-SAN-START sanboot
3.989 rbd: stack high-water 3360 of 8192 bytes (4832 left)
4.030 rbd: stack high-water 3960 of 8192 bytes (4232 left)
4.051 rbd: stack high-water 4344 of 8192 bytes (3848 left)
4.153 rbd: stack high-water 4648 of 8192 bytes (3544 left)
4.173 Registered SAN device 0x80
4.173 Booting from SAN device 0x80
4.215 rbd: stack high-water 4864 of 8192 bytes (3328 left)
4.975 rbd: stack high-water 5608 of 8192 bytes (2584 left)
6.245 GNU GRUB  version 2.14
6.245 
6.266 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
6.266       Press enter to boot the selected OS, `e' to edit the commands       
16.145       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
16.187 Starting systemd-udevd version 255.4-1ubuntu8.19
16.820 Begin: Loading essential drivers ... done.
16.841 Begin: Running /scripts/init-premount ... done.
16.862 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
16.862 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
17.168 RBFT-HOOK table found by source scan
17.168 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:d2
17.168 RBFT-HOOK nic: eth1 address 10.77.0.82/24
17.168 RBFT-HOOK table check (source scan):
17.454 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
17.454 RBFT PASS signature: rBFT
17.454 RBFT PASS length: 234 bytes
17.454 RBFT PASS acpi_revision: 1
17.454 RBFT PASS checksum: all 234 bytes sum to 0
17.454 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
17.454 RBFT PASS magic: WRBT
17.454 RBFT PASS version: 1
17.454 RBFT PASS header_len: 116
17.454 RBFT PASS reserved: all reserved bytes are zero
17.454 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.475 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.475 RBFT PASS namespace: absent (as in version 1)
17.475 RBFT PASS rules: every rule of the field table holds
17.475 RBFT PASS entity: wrtest-p2-b3
17.475 RBFT PASS pool: winrbd
17.475 RBFT PASS image: wrtest-p2-b3
17.475 RBFT PASS image_id: 39648e0b332d
17.475 RBFT PASS snapshot: absent, as expected
17.475 RBFT PASS auth: cephx
17.475 RBFT PASS msgr_mode: crc
17.475 RBFT PASS flags: key,static (0x6)
17.475 RBFT PASS flag_readonly: clear
17.475 RBFT PASS flag_key: set
17.496 RBFT PASS flag_nic_static: set
17.496 RBFT PASS flag_vlan: clear
17.496 RBFT PASS flag_fsid: clear
17.496 RBFT PASS flag_secure_required: clear
17.496 RBFT PASS key_type: aes
17.496 RBFT PASS key_len: 16
17.496 RBFT INFO key: present in the table (aes, 16 bytes), not printed
17.496 RBFT PASS mon_count: 1
17.496 RBFT PASS mon0: 10.77.0.10:3300
17.496 RBFT PASS fsid: none, as expected
17.496 RBFT PASS nic_mac: 52:54:00:77:12:d2
17.496 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d2 exists in this guest
17.517 RBFT PASS nic_vlan: 0
17.517 RBFT PASS nic_mtu: 1500
17.517 RBFT PASS nic_family: 4
17.517 RBFT PASS nic_ip: 10.77.0.82
17.517 RBFT PASS nic_prefix: 24
17.517 RBFT PASS nic_gateway: zero, as expected
17.517 RBFT PASS nic_dns: zero, as expected
17.517 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 91 46 45 4e 53 59 53
17.517 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
17.517 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
17.517 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
17.537 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d2 00 00
17.537 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 52 00 00 00 00 00 00 00 00
17.537 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.537 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.537 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
17.537 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
17.537 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
17.537 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
17.537 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
17.537 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
17.558 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
17.558 RBFT-RESULT PASS pass=40 fail=0 skip=0
17.558 WRBOOT-TABLE PASS
17.660 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
17.783 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
17.783 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
17.804 done.
17.804 Begin: Running /scripts/local-premount ... done.
47.918 Warning: fsck not present, so skipping root file system
47.939 done.
47.980 Begin: Running /scripts/local-bottom ... done.
48.000 Begin: Running /scripts/init-bottom ... done.
49.512 
49.512 Welcome to Ubuntu 24.04 LTS!
49.512 
50.371 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
50.371 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
50.371 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
50.371 [  OK  ] Created slice user.slice - User and Session Slice.
50.371 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
50.391 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
50.391 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
50.391          Expecting device dev-ttyS0.device - /dev/ttyS0...
50.391 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
50.391 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
50.391 [  OK  ] Reached target paths.target - Path Units.
50.412 [  OK  ] Reached target remote-fs.target - Remote File Systems.
50.412 [  OK  ] Reached target slices.target - Slice Units.
50.412 [  OK  ] Reached target swap.target - Swaps.
50.412 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
50.412 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
50.412 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
50.412 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
50.433 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
50.433 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
50.454          Mounting dev-hugepages.mount - Huge Pages File System...
50.454          Mounting dev-mqueue.mount - POSIX Message Queue File System...
50.474          Mounting sys-kernel-debug.mount - Kernel Debug File System...
50.474          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
50.495          Starting systemd-journald.service - Journal Service...
50.495          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
50.515          Starting modprobe@configfs.service - Load Kernel Module configfs...
50.556          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
50.556          Starting modprobe@drm.service - Load Kernel Module drm...
50.639          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
50.659          Starting modprobe@fuse.service - Load Kernel Module fuse...
50.680          Starting modprobe@loop.service - Load Kernel Module loop...
50.680          Starting systemd-modules-load.service - Load Kernel Modules...
50.700          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
50.742          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
50.742 [  OK  ] Started systemd-journald.service - Journal Service.
50.742 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
50.762 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
50.762 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
50.762 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
50.762 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
50.783 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
50.804 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
50.804 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
50.825 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
50.845 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
50.845 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
50.866 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
50.886          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
50.907          Mounting sys-kernel-config.mount - Kernel Configuration File System...
50.928          Starting systemd-sysctl.service - Apply Kernel Variables...
50.949          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
50.949 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
50.949 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
50.949 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
51.010          Starting systemd-random-seed.service - Load/Save OS Random Seed...
51.010 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
51.031 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
51.114 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
51.114 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
51.134          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
51.176 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
51.176 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
51.196          Mounting tmp.mount - /tmp...
51.196          Mounting var-cache.mount - /var/cache...
51.217          Mounting var-log.mount - /var/log...
51.238          Mounting var-tmp.mount - /var/tmp...
51.238          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
51.258 [  OK  ] Mounted tmp.mount - /tmp.
51.258 [  OK  ] Mounted var-cache.mount - /var/cache.
51.258 [  OK  ] Mounted var-log.mount - /var/log.
51.258 [  OK  ] Mounted var-tmp.mount - /var/tmp.
51.258 [  OK  ] Reached target local-fs.target - Local File Systems.
51.279 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
51.279 [  OK  ] Reached target sockets.target - Socket Units.
51.300          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
51.341 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
51.341          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
51.402 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
51.422          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
51.464 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
51.464 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
51.464 [  OK  ] Reached target sysinit.target - System Initialization.
51.485 [  OK  ] Started apt-daily.timer - Daily apt download activities.
51.485 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
51.485 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
51.485 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
51.485 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
51.485 [  OK  ] Started motd-news.timer - Message of the Day.
51.505 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
51.505 [  OK  ] Reached target timers.target - Timer Units.
51.505 [  OK  ] Reached target basic.target - Basic System.
51.505          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
51.526          Starting getty-static.service - geâ¦bus and logind are not available...
51.526          Starting systemd-user-sessions.service - Permit User Sessions...
51.547          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
51.630 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
51.650 [  OK  ] Started getty@tty1.service - Getty on tty1.
51.732 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
51.753 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
51.794 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
52.100 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
52.121 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
52.162 [  OK  ] Started getty@tty2.service - Getty on tty2.
52.182 [  OK  ] Started getty@tty3.service - Getty on tty3.
52.182 [  OK  ] Started getty@tty4.service - Getty on tty4.
52.203 [  OK  ] Started getty@tty5.service - Getty on tty5.
52.203 [  OK  ] Started getty@tty6.service - Getty on tty6.
52.203 [  OK  ] Reached target getty.target - Login Prompts.
52.366 WRBOOT-NET eth0 mac=52:54:00:77:11:52 
52.408 WRBOOT-NET eth1 mac=52:54:00:77:12:d2 10.77.0.82/24 fe80::5054:ff:fe77:12d2/64 
52.408 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
52.428 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
52.428 [  OK  ] Reached target multi-user.target - Multi-User System.
52.448 [  OK  ] Reached target graphical.target - Graphical Interface.
52.448          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
52.510 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
