# tailts start epoch=1795464774.872
0.890 iPXE initialising devices...
1.813 
1.813 
1.813 
1.813 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
1.813 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
1.834 WRRUN-STUB
5.082 Configuring (net0 52:54:00:77:11:49)...... ok
5.363 tftp://10.0.2.2/autoexec.ipxe... ok
5.448 WRRUN-BEGIN row=B2
5.573 Waiting for link-up on net1... ok
5.573 WRRUN-NET-OK
5.594 WRRUN-SAN-START sanboot
6.197 Registered SAN device 0x80
6.218 Booting from SAN device 0x80
8.605 GNU GRUB  version 2.14
8.605 
8.667 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
8.667       Press enter to boot the selected OS, `e' to edit the commands       
29.553       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
29.574 Starting systemd-udevd version 255.4-1ubuntu8.19
30.543 Begin: Loading essential drivers ... done.
30.543 Begin: Running /scripts/init-premount ... done.
30.584 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
30.584 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
31.323 RBFT-HOOK table found by source scan
31.323 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
31.323 RBFT-HOOK nic: eth1 address 10.77.0.73/24
31.323 RBFT-HOOK table check (source scan):
31.899 RBFT INFO source: scan: found at physical address 0x9e140 (1 valid copy/copies)
31.899 RBFT PASS signature: rBFT
31.899 RBFT PASS length: 234 bytes
31.899 RBFT PASS acpi_revision: 1
31.899 RBFT PASS checksum: all 234 bytes sum to 0
31.899 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
31.899 RBFT PASS magic: WRBT
31.920 RBFT PASS version: 1
31.920 RBFT PASS header_len: 116
31.920 RBFT PASS reserved: all reserved bytes are zero
31.920 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
31.920 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
31.920 RBFT PASS namespace: absent (as in version 1)
31.920 RBFT PASS rules: every rule of the field table holds
31.920 RBFT PASS entity: wrtest-p2-b2
31.920 RBFT PASS pool: winrbd
31.920 RBFT PASS image: wrtest-p2-b2
31.920 RBFT PASS image_id: 3956afc63637
31.962 RBFT PASS snapshot: absent, as expected
31.962 RBFT PASS auth: cephx
31.962 RBFT PASS msgr_mode: crc
31.962 RBFT PASS flags: key,static (0x6)
31.962 RBFT PASS flag_readonly: clear
31.962 RBFT PASS flag_key: set
31.962 RBFT PASS flag_nic_static: set
31.962 RBFT PASS flag_vlan: clear
31.962 RBFT PASS flag_fsid: clear
31.962 RBFT PASS flag_secure_required: clear
31.962 RBFT PASS key_type: aes
31.962 RBFT PASS key_len: 16
31.962 RBFT INFO key: present in the table (aes, 16 bytes), not printed
31.962 RBFT PASS mon_count: 1
31.962 RBFT PASS mon0: 10.77.0.10:3300
31.983 RBFT PASS fsid: none, as expected
31.983 RBFT PASS nic_mac: 52:54:00:77:12:c9
31.983 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
31.983 RBFT PASS nic_vlan: 0
31.983 RBFT PASS nic_mtu: 1500
31.983 RBFT PASS nic_family: 4
31.983 RBFT PASS nic_ip: 10.77.0.73
31.983 RBFT PASS nic_prefix: 24
31.983 RBFT PASS nic_gateway: zero, as expected
31.983 RBFT PASS nic_dns: zero, as expected
31.983 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 95 46 45 4e 53 59 53
31.983 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
32.004 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
32.004 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
32.004 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
32.004 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
32.004 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
32.004 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
32.004 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
32.004 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
32.004 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
32.004 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 39 35 36 61 66 63
32.025 RBFT DUMP 00c0: 36 33 36 33 37 00 04 00 e4 0c 0a 4d 00 0a 00 00
32.025 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
32.025 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
32.025 RBFT-RESULT PASS pass=40 fail=0 skip=0
32.025 WRBOOT-TABLE PASS
32.172 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
32.320 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
32.320 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
32.320 done.
32.341 Begin: Running /scripts/local-premount ... done.
62.447 Warning: fsck not present, so skipping root file system
62.467 done.
62.488 Begin: Running /scripts/local-bottom ... done.
62.509 Begin: Running /scripts/init-bottom ... done.
64.525 
64.546 Welcome to Ubuntu 24.04 LTS!
64.546 
66.087 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
66.107 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
66.107 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
66.107 [  OK  ] Created slice user.slice - User and Session Slice.
66.107 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
66.128 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
66.128 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
66.128          Expecting device dev-ttyS0.device - /dev/ttyS0...
66.128 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
66.128 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
66.149 [  OK  ] Reached target paths.target - Path Units.
66.149 [  OK  ] Reached target remote-fs.target - Remote File Systems.
66.149 [  OK  ] Reached target slices.target - Slice Units.
66.149 [  OK  ] Reached target swap.target - Swaps.
66.149 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
66.149 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
66.169 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
66.169 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
66.169 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
66.169 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
66.210          Mounting dev-hugepages.mount - Huge Pages File System...
66.210          Mounting dev-mqueue.mount - POSIX Message Queue File System...
66.231          Mounting sys-kernel-debug.mount - Kernel Debug File System...
66.231          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
66.252          Starting systemd-journald.service - Journal Service...
66.272          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
66.293          Starting modprobe@configfs.service - Load Kernel Module configfs...
66.314          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
66.334          Starting modprobe@drm.service - Load Kernel Module drm...
66.334          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
66.355          Starting modprobe@fuse.service - Load Kernel Module fuse...
66.376          Starting modprobe@loop.service - Load Kernel Module loop...
66.397          Starting systemd-modules-load.service - Load Kernel Modules...
66.418          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
66.439          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
66.460 [  OK  ] Started systemd-journald.service - Journal Service.
66.460 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
66.460 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
66.481 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
66.481 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
66.481 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
66.501 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
66.522 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
66.522 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
66.522 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
66.543 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
66.564 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
66.564 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
66.606          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
66.627          Mounting sys-kernel-config.mount - Kernel Configuration File System...
66.752          Starting systemd-sysctl.service - Apply Kernel Variables...
66.752          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
66.773 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
66.793 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
66.793 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
66.835          Starting systemd-random-seed.service - Load/Save OS Random Seed...
66.897 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
66.917 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
66.958 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
66.979          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
66.999 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
66.999 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
67.020 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
67.020          Mounting tmp.mount - /tmp...
67.041          Mounting var-cache.mount - /var/cache...
67.061          Mounting var-log.mount - /var/log...
67.061          Mounting var-tmp.mount - /var/tmp...
67.082          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
67.082 [  OK  ] Mounted tmp.mount - /tmp.
67.082 [  OK  ] Mounted var-cache.mount - /var/cache.
67.082 [  OK  ] Mounted var-log.mount - /var/log.
67.082 [  OK  ] Mounted var-tmp.mount - /var/tmp.
67.103 [  OK  ] Reached target local-fs.target - Local File Systems.
67.103 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
67.103 [  OK  ] Reached target sockets.target - Socket Units.
67.124          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
67.165 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
67.165          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
67.248 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
67.248          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
67.289 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
67.433 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
67.433 [  OK  ] Reached target sysinit.target - System Initialization.
67.433 [  OK  ] Started apt-daily.timer - Daily apt download activities.
67.433 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
67.453 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
67.453 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
67.453 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
67.453 [  OK  ] Started motd-news.timer - Message of the Day.
67.453 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
67.474 [  OK  ] Reached target timers.target - Timer Units.
67.474 [  OK  ] Reached target basic.target - Basic System.
67.474          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
67.495          Starting getty-static.service - geâ¦bus and logind are not available...
67.515          Starting systemd-user-sessions.service - Permit User Sessions...
67.536          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
67.557 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
67.598 [  OK  ] Started getty@tty1.service - Getty on tty1.
67.729 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
67.729 WRBOOT-EDD int13_dev81 mbr_signature=-
67.791 [  OK  ] Started getty@tty2.service - Getty on tty2.
67.812 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
67.895 [  OK  ] Started getty@tty3.service - Getty on tty3.
67.916 [  OK  ] Started getty@tty4.service - Getty on tty4.
67.998 [  OK  ] Started getty@tty5.service - Getty on tty5.
68.019 [  OK  ] Started getty@tty6.service - Getty on tty6.
68.060 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
68.080 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
68.080 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
68.080 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
68.101 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
68.121 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
68.142 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
68.203 [  OK  ] Reached target getty.target - Login Prompts.
68.203 [  OK  ] Reached target multi-user.target - Multi-User System.
68.203 [  OK  ] Reached target graphical.target - Graphical Interface.
68.224          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
68.265 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
