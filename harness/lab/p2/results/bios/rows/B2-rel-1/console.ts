# tailts start epoch=1795463261.456
0.123 iPXE initialising devices...
0.572 
0.572 
0.572 
0.593 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.613 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.613 WRRUN-STUB
3.737 Configuring (net0 52:54:00:77:11:49)...... ok
3.737 tftp://10.0.2.2/autoexec.ipxe... ok
3.737 WRRUN-BEGIN row=B2
3.778 Waiting for link-up on net1... ok
3.778 WRRUN-NET-OK
3.798 WRRUN-SAN-START sanboot
4.003 Registered SAN device 0x80
4.003 Booting from SAN device 0x80
5.002 GNU GRUB  version 2.14
5.002 
5.043 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.043       Press enter to boot the selected OS, `e' to edit the commands       
17.476       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
17.497 Starting systemd-udevd version 255.4-1ubuntu8.19
18.089 Begin: Loading essential drivers ... done.
18.089 Begin: Running /scripts/init-premount ... done.
18.110 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
18.110 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
18.376 RBFT-HOOK table found by source scan
18.376 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
18.396 RBFT-HOOK nic: eth1 address 10.77.0.73/24
18.396 RBFT-HOOK table check (source scan):
18.662 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
18.662 RBFT PASS signature: rBFT
18.662 RBFT PASS length: 234 bytes
18.662 RBFT PASS acpi_revision: 1
18.662 RBFT PASS checksum: all 234 bytes sum to 0
18.662 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
18.662 RBFT PASS magic: WRBT
18.662 RBFT PASS version: 1
18.662 RBFT PASS header_len: 116
18.662 RBFT PASS reserved: all reserved bytes are zero
18.683 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
18.683 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
18.683 RBFT PASS namespace: absent (as in version 1)
18.683 RBFT PASS rules: every rule of the field table holds
18.683 RBFT PASS entity: wrtest-p2-b2
18.683 RBFT PASS pool: winrbd
18.683 RBFT PASS image: wrtest-p2-b2
18.683 RBFT PASS image_id: 3956afc63637
18.683 RBFT PASS snapshot: absent, as expected
18.683 RBFT PASS auth: cephx
18.683 RBFT PASS msgr_mode: crc
18.683 RBFT PASS flags: key,static (0x6)
18.683 RBFT PASS flag_readonly: clear
18.683 RBFT PASS flag_key: set
18.683 RBFT PASS flag_nic_static: set
18.683 RBFT PASS flag_vlan: clear
18.703 RBFT PASS flag_fsid: clear
18.703 RBFT PASS flag_secure_required: clear
18.703 RBFT PASS key_type: aes
18.703 RBFT PASS key_len: 16
18.703 RBFT INFO key: present in the table (aes, 16 bytes), not printed
18.703 RBFT PASS mon_count: 1
18.703 RBFT PASS mon0: 10.77.0.10:3300
18.703 RBFT PASS fsid: none, as expected
18.703 RBFT PASS nic_mac: 52:54:00:77:12:c9
18.703 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
18.703 RBFT PASS nic_vlan: 0
18.703 RBFT PASS nic_mtu: 1500
18.703 RBFT PASS nic_family: 4
18.703 RBFT PASS nic_ip: 10.77.0.73
18.703 RBFT PASS nic_prefix: 24
18.703 RBFT PASS nic_gateway: zero, as expected
18.724 RBFT PASS nic_dns: zero, as expected
18.724 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 95 46 45 4e 53 59 53
18.724 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
18.724 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
18.724 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
18.724 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
18.724 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
18.724 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.724 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.724 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
18.745 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
18.745 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
18.745 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 39 35 36 61 66 63
18.745 RBFT DUMP 00c0: 36 33 36 33 37 00 04 00 e4 0c 0a 4d 00 0a 00 00
18.745 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
18.745 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
18.745 RBFT-RESULT PASS pass=40 fail=0 skip=0
18.745 WRBOOT-TABLE PASS
18.806 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
18.888 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
18.888 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
18.888 done.
18.888 Begin: Running /scripts/local-premount ... done.
48.957 Warning: fsck not present, so skipping root file system
48.977 done.
48.998 Begin: Running /scripts/local-bottom ... done.
49.018 Begin: Running /scripts/init-bottom ... done.
50.472 
50.472 Welcome to Ubuntu 24.04 LTS!
50.472 
51.495 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
51.495 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
51.495 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
51.522 [  OK  ] Created slice user.slice - User and Session Slice.
51.522 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
51.522 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
51.522 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
51.522          Expecting device dev-ttyS0.device - /dev/ttyS0...
51.543 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
51.543 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
51.543 [  OK  ] Reached target paths.target - Path Units.
51.543 [  OK  ] Reached target remote-fs.target - Remote File Systems.
51.543 [  OK  ] Reached target slices.target - Slice Units.
51.543 [  OK  ] Reached target swap.target - Swaps.
51.563 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
51.563 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
51.563 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
51.563 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
51.563 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
51.584 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
51.584          Mounting dev-hugepages.mount - Huge Pages File System...
51.605          Mounting dev-mqueue.mount - POSIX Message Queue File System...
51.605          Mounting sys-kernel-debug.mount - Kernel Debug File System...
51.626          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
51.646          Starting systemd-journald.service - Journal Service...
51.667          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
51.667          Starting modprobe@configfs.service - Load Kernel Module configfs...
51.667          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
51.688          Starting modprobe@drm.service - Load Kernel Module drm...
51.709          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
51.709          Starting modprobe@fuse.service - Load Kernel Module fuse...
51.729          Starting modprobe@loop.service - Load Kernel Module loop...
51.750          Starting systemd-modules-load.service - Load Kernel Modules...
51.771          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
51.791          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
51.791 [  OK  ] Started systemd-journald.service - Journal Service.
51.791 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
51.812 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
51.812 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
51.812 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
51.812 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
51.812 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
51.833 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
51.833 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
51.833 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
51.833 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
51.855 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
51.855 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
51.896          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
51.896          Mounting sys-kernel-config.mount - Kernel Configuration File System...
51.917          Starting systemd-sysctl.service - Apply Kernel Variables...
51.917          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
51.917 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
51.937 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
51.979 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
52.142 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
52.162          Starting systemd-random-seed.service - Load/Save OS Random Seed...
52.183 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
52.495 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
52.495          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
52.516 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
52.537 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
52.557          Mounting tmp.mount - /tmp...
52.557          Mounting var-cache.mount - /var/cache...
52.578          Mounting var-log.mount - /var/log...
52.599          Mounting var-tmp.mount - /var/tmp...
52.599          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
52.620 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
52.620 [  OK  ] Mounted tmp.mount - /tmp.
52.620 [  OK  ] Mounted var-cache.mount - /var/cache.
52.640 [  OK  ] Mounted var-log.mount - /var/log.
52.640 [  OK  ] Mounted var-tmp.mount - /var/tmp.
52.640 [  OK  ] Reached target local-fs.target - Local File Systems.
52.661 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
52.661 [  OK  ] Reached target sockets.target - Socket Units.
52.661          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
52.682 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
52.702          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
52.785 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
52.806          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
52.826 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
52.928 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
52.928 [  OK  ] Reached target sysinit.target - System Initialization.
52.928 [  OK  ] Started apt-daily.timer - Daily apt download activities.
52.928 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
52.949 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
52.949 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
52.949 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
52.949 [  OK  ] Started motd-news.timer - Message of the Day.
52.970 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
52.970 [  OK  ] Reached target timers.target - Timer Units.
52.970 [  OK  ] Reached target basic.target - Basic System.
52.990          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
53.011          Starting getty-static.service - geâ¦bus and logind are not available...
53.031          Starting systemd-user-sessions.service - Permit User Sessions...
53.076          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
53.097 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
53.138 [  OK  ] Started getty@tty1.service - Getty on tty1.
53.158 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
53.179 WRBOOT-EDD int13_dev81 mbr_signature=-
53.179 [  OK  ] Started getty@tty2.service - Getty on tty2.
53.513 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
53.555 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
53.555 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
53.575 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
53.575 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
53.596 [  OK  ] Started getty@tty3.service - Getty on tty3.
53.617 [  OK  ] Started getty@tty4.service - Getty on tty4.
53.617 [  OK  ] Started getty@tty5.service - Getty on tty5.
53.637 [  OK  ] Started getty@tty6.service - Getty on tty6.
53.658 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
53.658 [  OK  ] Reached target getty.target - Login Prompts.
53.679 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
53.699 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
53.699 [  OK  ] Reached target multi-user.target - Multi-User System.
53.720 [  OK  ] Reached target graphical.target - Graphical Interface.
53.720          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
53.761 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
