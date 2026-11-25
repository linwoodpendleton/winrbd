# tailts start epoch=1795480349.086
0.000 iPXE initialising devices...
0.185 
0.185 
0.185 
0.206 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.206 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.206 WRRUN-STUB
3.343 Configuring (net0 52:54:00:77:11:4a)...... ok
3.343 tftp://10.0.2.2/autoexec.ipxe... ok
3.343 WRRUN-BEGIN row=B3
3.404 Waiting for link-up on net1... ok
3.404 WRRUN-NET-OK
3.404 WRRUN-SAN-START sanboot
3.425 rbd: stack high-water 2096 of 16384 bytes (14288 left)
3.466 rbd: stack high-water 2696 of 16384 bytes (13688 left)
3.487 rbd: stack high-water 2980 of 16384 bytes (13404 left)
3.938 rbd: stack high-water 3232 of 16384 bytes (13152 left)
3.959 Registered SAN device 0x80
3.959 Booting from SAN device 0x80
3.980 rbd: stack high-water 3380 of 16384 bytes (13004 left)
4.451 rbd: stack high-water 4048 of 16384 bytes (12336 left)
5.782 GNU GRUB  version 2.14
5.782 
5.803 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.803       Press enter to boot the selected OS, `e' to edit the commands       
12.303       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
12.344 Starting systemd-udevd version 255.4-1ubuntu8.19
12.919 Begin: Loading essential drivers ... done.
12.919 Begin: Running /scripts/init-premount ... done.
12.940 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
12.940 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
13.226 RBFT-HOOK table found by source scan
13.226 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
13.247 RBFT-HOOK nic: eth1 address 10.77.0.74/24
13.247 RBFT-HOOK table check (source scan):
13.514 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
13.514 RBFT PASS signature: rBFT
13.514 RBFT PASS length: 234 bytes
13.514 RBFT PASS acpi_revision: 1
13.535 RBFT PASS checksum: all 234 bytes sum to 0
13.535 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
13.535 RBFT PASS magic: WRBT
13.535 RBFT PASS version: 1
13.535 RBFT PASS header_len: 116
13.535 RBFT PASS reserved: all reserved bytes are zero
13.535 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
13.535 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
13.535 RBFT PASS namespace: absent (as in version 1)
13.535 RBFT PASS rules: every rule of the field table holds
13.535 RBFT PASS entity: wrtest-p2-b3
13.535 RBFT PASS pool: winrbd
13.535 RBFT PASS image: wrtest-p2-b3
13.535 RBFT PASS image_id: 3fc6592539a3
13.535 RBFT PASS snapshot: absent, as expected
13.535 RBFT PASS auth: cephx
13.535 RBFT PASS msgr_mode: crc
13.556 RBFT PASS flags: key,static (0x6)
13.556 RBFT PASS flag_readonly: clear
13.556 RBFT PASS flag_key: set
13.556 RBFT PASS flag_nic_static: set
13.556 RBFT PASS flag_vlan: clear
13.556 RBFT PASS flag_fsid: clear
13.556 RBFT PASS flag_secure_required: clear
13.556 RBFT PASS key_type: aes
13.556 RBFT PASS key_len: 16
13.556 RBFT INFO key: present in the table (aes, 16 bytes), not printed
13.556 RBFT PASS mon_count: 1
13.556 RBFT PASS mon0: 10.77.0.10:3300
13.556 RBFT PASS fsid: none, as expected
13.556 RBFT PASS nic_mac: 52:54:00:77:12:ca
13.556 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
13.556 RBFT PASS nic_vlan: 0
13.556 RBFT PASS nic_mtu: 1500
13.556 RBFT PASS nic_family: 4
13.556 RBFT PASS nic_ip: 10.77.0.74
13.556 RBFT PASS nic_prefix: 24
13.556 RBFT PASS nic_gateway: zero, as expected
13.556 RBFT PASS nic_dns: zero, as expected
13.556 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 94 46 45 4e 53 59 53
13.624 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
13.624 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
13.624 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
13.624 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
13.644 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
13.644 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
13.644 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
13.644 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
13.644 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
13.644 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
13.644 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 66 63 36 35 39 32
13.644 RBFT DUMP 00c0: 35 33 39 61 33 00 04 00 e4 0c 0a 4d 00 0a 00 00
13.644 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
13.644 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
13.644 RBFT-RESULT PASS pass=40 fail=0 skip=0
13.644 WRBOOT-TABLE PASS
13.707 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
15.305 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
15.305 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
15.305 done.
15.325 Begin: Running /scripts/local-premount ... done.
45.671 Warning: fsck not present, so skipping root file system
45.713 done.
45.734 Begin: Running /scripts/local-bottom ... done.
45.754 Begin: Running /scripts/init-bottom ... done.
48.760 
48.760 Welcome to Ubuntu 24.04 LTS!
48.760 
50.934 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
50.934 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
50.956 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
50.956 [  OK  ] Created slice user.slice - User and Session Slice.
50.956 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
50.956 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
50.956 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
50.956          Expecting device dev-ttyS0.device - /dev/ttyS0...
50.977 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
50.977 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
50.977 [  OK  ] Reached target paths.target - Path Units.
50.977 [  OK  ] Reached target remote-fs.target - Remote File Systems.
50.977 [  OK  ] Reached target slices.target - Slice Units.
50.977 [  OK  ] Reached target swap.target - Swaps.
50.977 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
50.998 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
50.998 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
50.998 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
50.998 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
51.018 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
51.018          Mounting dev-hugepages.mount - Huge Pages File System...
51.040          Mounting dev-mqueue.mount - POSIX Message Queue File System...
51.040          Mounting sys-kernel-debug.mount - Kernel Debug File System...
51.061          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
51.081          Starting systemd-journald.service - Journal Service...
51.081          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
51.102          Starting modprobe@configfs.service - Load Kernel Module configfs...
51.123          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
51.144          Starting modprobe@drm.service - Load Kernel Module drm...
51.164          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
51.185          Starting modprobe@fuse.service - Load Kernel Module fuse...
51.206          Starting modprobe@loop.service - Load Kernel Module loop...
51.227          Starting systemd-modules-load.service - Load Kernel Modules...
51.227          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
51.247          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
51.247 [  OK  ] Started systemd-journald.service - Journal Service.
51.247 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
51.247 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
51.268 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
51.268 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
51.268 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
51.289 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
51.289 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
51.289 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
51.310 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
51.310 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
51.331 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
51.331 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
51.372          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
51.372          Mounting sys-kernel-config.mount - Kernel Configuration File System...
51.393          Starting systemd-sysctl.service - Apply Kernel Variables...
51.414          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
51.435 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
51.435 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
51.456 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
51.497          Starting systemd-random-seed.service - Load/Save OS Random Seed...
51.538 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
51.580 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
51.621 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
51.621 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
51.642          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
51.662 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
51.662 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
51.683          Mounting tmp.mount - /tmp...
51.704          Mounting var-cache.mount - /var/cache...
51.704          Mounting var-log.mount - /var/log...
51.725          Mounting var-tmp.mount - /var/tmp...
51.725          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
51.725 [  OK  ] Mounted tmp.mount - /tmp.
51.745 [  OK  ] Mounted var-cache.mount - /var/cache.
51.745 [  OK  ] Mounted var-log.mount - /var/log.
51.745 [  OK  ] Mounted var-tmp.mount - /var/tmp.
51.745 [  OK  ] Reached target local-fs.target - Local File Systems.
51.766 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
51.766 [  OK  ] Reached target sockets.target - Socket Units.
51.787          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
51.807 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
51.828          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
51.869 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
51.890          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
51.932 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
52.055 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
52.055 [  OK  ] Reached target sysinit.target - System Initialization.
52.076 [  OK  ] Started apt-daily.timer - Daily apt download activities.
52.076 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
52.076 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
52.076 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
52.096 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
52.096 [  OK  ] Started motd-news.timer - Message of the Day.
52.096 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
52.096 [  OK  ] Reached target timers.target - Timer Units.
52.117 [  OK  ] Reached target basic.target - Basic System.
52.138          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
52.159          Starting getty-static.service - geâ¦bus and logind are not available...
52.159          Starting systemd-user-sessions.service - Permit User Sessions...
52.200          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
52.241 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
52.262 [  OK  ] Started getty@tty1.service - Getty on tty1.
52.365 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
52.427 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
52.448 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
52.510 [  OK  ] Started getty@tty2.service - Getty on tty2.
52.510 [  OK  ] Started getty@tty3.service - Getty on tty3.
52.510 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
52.531 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
52.552 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
52.552 [  OK  ] Started getty@tty4.service - Getty on tty4.
52.552 [  OK  ] Started getty@tty5.service - Getty on tty5.
52.593 [  OK  ] Started getty@tty6.service - Getty on tty6.
52.593 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
52.614 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
52.614 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
52.614 [  OK  ] Reached target getty.target - Login Prompts.
52.614 [  OK  ] Reached target multi-user.target - Multi-User System.
52.634 [  OK  ] Reached target graphical.target - Graphical Interface.
52.634          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
52.675 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
