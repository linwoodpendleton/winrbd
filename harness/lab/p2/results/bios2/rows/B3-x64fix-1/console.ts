# tailts start epoch=1795482527.706
0.021 iPXE initialising devices...
0.104 
0.104 
0.104 
0.125 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.166 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.166 WRRUN-STUB
3.420 Configuring (net0 52:54:00:77:11:4a)...... ok
3.441 tftp://10.0.2.2/autoexec.ipxe... ok
3.441 WRRUN-BEGIN row=B3
3.482 Waiting for link-up on net1... ok
3.482 WRRUN-NET-OK
3.482 WRRUN-SAN-START sanboot
3.524 rbd: stack high-water 3360 of 8192 bytes (4832 left)
3.587 rbd: stack high-water 3960 of 8192 bytes (4232 left)
3.587 rbd: stack high-water 4344 of 8192 bytes (3848 left)
3.794 rbd: stack high-water 4648 of 8192 bytes (3544 left)
3.815 Registered SAN device 0x80
3.815 Booting from SAN device 0x80
3.836 rbd: stack high-water 4864 of 8192 bytes (3328 left)
5.774 rbd: stack high-water 5608 of 8192 bytes (2584 left)
6.986 GNU GRUB  version 2.14
6.986 
7.007 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
7.007       Press enter to boot the selected OS, `e' to edit the commands       
15.714       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
15.756 Starting systemd-udevd version 255.4-1ubuntu8.19
16.514 Begin: Loading essential drivers ... done.
16.514 Begin: Running /scripts/init-premount ... done.
16.555 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
16.555 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
16.821 RBFT-HOOK table found by source scan
16.821 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
16.821 RBFT-HOOK nic: eth1 address 10.77.0.74/24
16.821 RBFT-HOOK table check (source scan):
17.087 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
17.087 RBFT PASS signature: rBFT
17.087 RBFT PASS length: 234 bytes
17.087 RBFT PASS acpi_revision: 1
17.087 RBFT PASS checksum: all 234 bytes sum to 0
17.087 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
17.087 RBFT PASS magic: WRBT
17.087 RBFT PASS version: 1
17.087 RBFT PASS header_len: 116
17.087 RBFT PASS reserved: all reserved bytes are zero
17.087 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.108 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.108 RBFT PASS namespace: absent (as in version 1)
17.108 RBFT PASS rules: every rule of the field table holds
17.108 RBFT PASS entity: wrtest-p2-b3
17.108 RBFT PASS pool: winrbd
17.108 RBFT PASS image: wrtest-p2-b3
17.108 RBFT PASS image_id: 3fc6592539a3
17.108 RBFT PASS snapshot: absent, as expected
17.108 RBFT PASS auth: cephx
17.108 RBFT PASS msgr_mode: crc
17.108 RBFT PASS flags: key,static (0x6)
17.108 RBFT PASS flag_readonly: clear
17.108 RBFT PASS flag_key: set
17.108 RBFT PASS flag_nic_static: set
17.108 RBFT PASS flag_vlan: clear
17.108 RBFT PASS flag_fsid: clear
17.108 RBFT PASS flag_secure_required: clear
17.108 RBFT PASS key_type: aes
17.108 RBFT PASS key_len: 16
17.108 RBFT INFO key: present in the table (aes, 16 bytes), not printed
17.108 RBFT PASS mon_count: 1
17.108 RBFT PASS mon0: 10.77.0.10:3300
17.129 RBFT PASS fsid: none, as expected
17.129 RBFT PASS nic_mac: 52:54:00:77:12:ca
17.129 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
17.129 RBFT PASS nic_vlan: 0
17.129 RBFT PASS nic_mtu: 1500
17.129 RBFT PASS nic_family: 4
17.150 RBFT PASS nic_ip: 10.77.0.74
17.150 RBFT PASS nic_prefix: 24
17.171 RBFT PASS nic_gateway: zero, as expected
17.212 RBFT PASS nic_dns: zero, as expected
17.339 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 94 46 45 4e 53 59 53
17.339 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
17.359 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
17.359 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
17.359 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
17.359 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
17.359 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.359 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.359 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
17.359 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
17.359 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
17.359 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 66 63 36 35 39 32
17.359 RBFT DUMP 00c0: 35 33 39 61 33 00 04 00 e4 0c 0a 4d 00 0a 00 00
17.380 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
17.380 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
17.380 RBFT-RESULT PASS pass=40 fail=0 skip=0
17.380 WRBOOT-TABLE PASS
17.463 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
17.525 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
17.525 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
17.525 done.
17.525 Begin: Running /scripts/local-premount ... done.
47.625 Warning: fsck not present, so skipping root file system
47.645 done.
47.667 Begin: Running /scripts/local-bottom ... done.
47.688 Begin: Running /scripts/init-bottom ... done.
48.916 
48.916 Welcome to Ubuntu 24.04 LTS!
48.936 
50.043 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
50.043 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
50.043 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
50.043 [  OK  ] Created slice user.slice - User and Session Slice.
50.064 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
50.064 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
50.064 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
50.064          Expecting device dev-ttyS0.device - /dev/ttyS0...
50.064 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
50.064 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
50.064 [  OK  ] Reached target paths.target - Path Units.
50.084 [  OK  ] Reached target remote-fs.target - Remote File Systems.
50.084 [  OK  ] Reached target slices.target - Slice Units.
50.084 [  OK  ] Reached target swap.target - Swaps.
50.084 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
50.084 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
50.084 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
50.084 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
50.105 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
50.105 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
50.126          Mounting dev-hugepages.mount - Huge Pages File System...
50.126          Mounting dev-mqueue.mount - POSIX Message Queue File System...
50.354          Mounting sys-kernel-debug.mount - Kernel Debug File System...
50.374          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
50.395          Starting systemd-journald.service - Journal Service...
50.395          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
50.416          Starting modprobe@configfs.service - Load Kernel Module configfs...
50.436          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
50.457          Starting modprobe@drm.service - Load Kernel Module drm...
50.478          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
50.478          Starting modprobe@fuse.service - Load Kernel Module fuse...
50.498          Starting modprobe@loop.service - Load Kernel Module loop...
50.519          Starting systemd-modules-load.service - Load Kernel Modules...
50.539          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
50.560          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
50.560 [  OK  ] Started systemd-journald.service - Journal Service.
50.581 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
50.581 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
50.581 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
50.602 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
50.602 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
50.686 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
50.686 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
50.707 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
50.707 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
50.728 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
50.728 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
50.748 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
50.769          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
50.790          Mounting sys-kernel-config.mount - Kernel Configuration File System...
50.790          Starting systemd-sysctl.service - Apply Kernel Variables...
50.811          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
50.831 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
50.831 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
50.852 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
50.893          Starting systemd-random-seed.service - Load/Save OS Random Seed...
50.934 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
50.955 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
50.996 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
51.017          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
51.038 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
51.038 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
51.058          Mounting tmp.mount - /tmp...
51.079          Mounting var-cache.mount - /var/cache...
51.099          Mounting var-log.mount - /var/log...
51.099          Mounting var-tmp.mount - /var/tmp...
51.120          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
51.120 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
51.120 [  OK  ] Mounted tmp.mount - /tmp.
51.141 [  OK  ] Mounted var-cache.mount - /var/cache.
51.244 [  OK  ] Mounted var-log.mount - /var/log.
51.244 [  OK  ] Mounted var-tmp.mount - /var/tmp.
51.244 [  OK  ] Reached target local-fs.target - Local File Systems.
51.265 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
51.265 [  OK  ] Reached target sockets.target - Socket Units.
51.286          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
51.327 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
51.327          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
51.410 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
51.410          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
51.451 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
51.554 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
51.554 [  OK  ] Reached target sysinit.target - System Initialization.
51.554 [  OK  ] Started apt-daily.timer - Daily apt download activities.
51.554 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
51.554 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
51.574 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
51.574 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
51.574 [  OK  ] Started motd-news.timer - Message of the Day.
51.574 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
51.574 [  OK  ] Reached target timers.target - Timer Units.
51.595 [  OK  ] Reached target basic.target - Basic System.
51.595          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
51.616          Starting getty-static.service - geâ¦bus and logind are not available...
51.636          Starting systemd-user-sessions.service - Permit User Sessions...
51.678          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
51.698 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
51.719 [  OK  ] Started getty@tty1.service - Getty on tty1.
51.760 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
51.781 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
51.781 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
51.843 [  OK  ] Started getty@tty2.service - Getty on tty2.
51.864 [  OK  ] Started getty@tty3.service - Getty on tty3.
51.947 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
51.988 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
51.988 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
52.009 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
52.029 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
52.029 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
52.050 [  OK  ] Started getty@tty4.service - Getty on tty4.
52.050 [  OK  ] Started getty@tty5.service - Getty on tty5.
52.070 [  OK  ] Started getty@tty6.service - Getty on tty6.
52.091 [  OK  ] Reached target getty.target - Login Prompts.
52.091 [  OK  ] Reached target multi-user.target - Multi-User System.
52.091 [  OK  ] Reached target graphical.target - Graphical Interface.
52.112          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
52.371 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
