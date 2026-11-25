# tailts start epoch=1795479982.481
7.831 iPXE initialising devices...
7.874 
7.874 
7.895 
7.938 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.959 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.959 WRRUN-STUB
11.015 Configuring (net0 52:54:00:77:12:c7)...... ok
11.036 tftp://10.77.0.10/autoexec.ipxe... ok
11.057 WRRUN-BEGIN row=B1
11.120 Waiting for link-up on net0... ok
11.141 WRRUN-NET-OK
11.162 WRRUN-SAN-START sanboot
11.203 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.224 rbd: core stack high-water 512 of 16384 bytes
11.266 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.287 rbd: core stack high-water 788 of 16384 bytes
11.309 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.330 rbd: core stack high-water 1304 of 16384 bytes
11.371 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.392 rbd: core stack high-water 1588 of 16384 bytes
11.516 Registered SAN device 0x80
11.537 Booting from SAN device 0x80
11.579 rbd: stack high-water 2784 of 4096 bytes (1312 left)
11.600 rbd: core stack high-water 1696 of 16384 bytes
14.240 GNU GRUB  version 2.14
14.240 
14.261 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.282       Press enter to boot the selected OS, `e' to edit the commands       
26.181       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
26.202 Starting systemd-udevd version 255.4-1ubuntu8.19
26.817 Begin: Loading essential drivers ... done.
26.817 Begin: Running /scripts/init-premount ... done.
26.858 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
26.858 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
27.166 RBFT-HOOK table found by source scan
27.166 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
27.187 RBFT-HOOK nic: eth0 address 10.77.0.71/24
27.187 RBFT-HOOK table check (source scan):
27.433 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
27.433 RBFT PASS signature: rBFT
27.433 RBFT PASS length: 234 bytes
27.433 RBFT PASS acpi_revision: 1
27.433 RBFT PASS checksum: all 234 bytes sum to 0
27.433 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
27.433 RBFT PASS magic: WRBT
27.433 RBFT PASS version: 1
27.433 RBFT PASS header_len: 116
27.433 RBFT PASS reserved: all reserved bytes are zero
27.454 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
27.454 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
27.454 RBFT PASS namespace: absent (as in version 1)
27.454 RBFT PASS rules: every rule of the field table holds
27.454 RBFT PASS entity: wrtest-p2-b1
27.454 RBFT PASS pool: winrbd
27.454 RBFT PASS image: wrtest-p2-b1
27.454 RBFT PASS image_id: 3fae3418fe30
27.454 RBFT PASS snapshot: absent, as expected
27.454 RBFT PASS auth: cephx
27.454 RBFT PASS msgr_mode: crc
27.454 RBFT PASS flags: key,static (0x6)
27.454 RBFT PASS flag_readonly: clear
27.454 RBFT PASS flag_key: set
27.454 RBFT PASS flag_nic_static: set
27.454 RBFT PASS flag_vlan: clear
27.454 RBFT PASS flag_fsid: clear
27.454 RBFT PASS flag_secure_required: clear
27.454 RBFT PASS key_type: aes
27.475 RBFT PASS key_len: 16
27.475 RBFT INFO key: present in the table (aes, 16 bytes), not printed
27.475 RBFT PASS mon_count: 1
27.475 RBFT PASS mon0: 10.77.0.10:3300
27.475 RBFT PASS fsid: none, as expected
27.475 RBFT PASS nic_mac: 52:54:00:77:12:c7
27.475 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
27.475 RBFT PASS nic_vlan: 0
27.475 RBFT PASS nic_mtu: 1500
27.475 RBFT PASS nic_family: 4
27.475 RBFT PASS nic_ip: 10.77.0.71
27.475 RBFT PASS nic_prefix: 24
27.475 RBFT PASS nic_gateway: zero, as expected
27.475 RBFT PASS nic_dns: zero, as expected
27.475 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
27.475 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
27.496 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
27.496 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
27.496 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
27.496 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
27.496 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
27.496 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
27.496 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
27.496 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
27.496 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
27.496 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
27.496 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
27.516 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
27.516 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
27.516 RBFT-RESULT PASS pass=40 fail=0 skip=0
27.516 WRBOOT-TABLE PASS
27.578 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
27.619 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
27.619 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
27.619 done.
27.640 Begin: Running /scripts/local-premount ... done.
57.720 Warning: fsck not present, so skipping root file system
57.740 done.
57.761 Begin: Running /scripts/local-bottom ... done.
57.782 Begin: Running /scripts/init-bottom ... done.
58.850 
58.850 Welcome to Ubuntu 24.04 LTS!
58.850 
59.588 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
59.588 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
59.588 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
59.588 [  OK  ] Created slice user.slice - User and Session Slice.
59.588 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
59.609 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
59.609 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
59.609          Expecting device dev-ttyS0.device - /dev/ttyS0...
59.609 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
59.609 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
59.609 [  OK  ] Reached target paths.target - Path Units.
59.629 [  OK  ] Reached target remote-fs.target - Remote File Systems.
59.629 [  OK  ] Reached target slices.target - Slice Units.
59.629 [  OK  ] Reached target swap.target - Swaps.
59.629 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
59.629 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
59.629 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
59.651 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
59.651 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
59.651 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
59.672          Mounting dev-hugepages.mount - Huge Pages File System...
59.672          Mounting dev-mqueue.mount - POSIX Message Queue File System...
59.692          Mounting sys-kernel-debug.mount - Kernel Debug File System...
59.692          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
59.713          Starting systemd-journald.service - Journal Service...
59.733          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
59.754          Starting modprobe@configfs.service - Load Kernel Module configfs...
59.775          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
59.775          Starting modprobe@drm.service - Load Kernel Module drm...
59.796          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
59.817          Starting modprobe@fuse.service - Load Kernel Module fuse...
59.817          Starting modprobe@loop.service - Load Kernel Module loop...
59.837          Starting systemd-modules-load.service - Load Kernel Modules...
59.858          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
59.858          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
59.879 [  OK  ] Started systemd-journald.service - Journal Service.
59.879 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
59.879 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
59.899 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
59.899 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
59.899 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
59.920 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
59.920 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
59.920 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
59.941 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
59.941 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
59.941 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
59.961 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
59.961 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
59.982          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
60.003          Mounting sys-kernel-config.mount - Kernel Configuration File System...
60.024          Starting systemd-random-seed.service - Load/Save OS Random Seed...
60.044          Starting systemd-sysctl.service - Apply Kernel Variables...
60.065          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
60.065 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
60.065 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
60.065 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
60.148 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
60.189 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
60.189          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
60.231 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
60.252 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
60.274          Mounting tmp.mount - /tmp...
60.295          Mounting var-cache.mount - /var/cache...
60.316          Mounting var-log.mount - /var/log...
60.316          Mounting var-tmp.mount - /var/tmp...
60.337          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
60.358 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
60.358 [  OK  ] Mounted tmp.mount - /tmp.
60.358 [  OK  ] Mounted var-cache.mount - /var/cache.
60.358 [  OK  ] Mounted var-log.mount - /var/log.
60.358 [  OK  ] Mounted var-tmp.mount - /var/tmp.
60.380 [  OK  ] Reached target local-fs.target - Local File Systems.
60.401 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
60.401 [  OK  ] Reached target sockets.target - Socket Units.
60.422          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
60.465 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
60.465          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
60.527 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
60.548          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
60.570 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
60.612 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
60.612 [  OK  ] Reached target sysinit.target - System Initialization.
60.634 [  OK  ] Started apt-daily.timer - Daily apt download activities.
60.634 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
60.634 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
60.634 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
60.634 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
60.656 [  OK  ] Started motd-news.timer - Message of the Day.
60.656 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
60.656 [  OK  ] Reached target timers.target - Timer Units.
60.656 [  OK  ] Reached target basic.target - Basic System.
60.678          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
60.721          Starting getty-static.service - geâ¦bus and logind are not available...
60.742          Starting systemd-user-sessions.service - Permit User Sessions...
60.786          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
60.849 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
60.913 [  OK  ] Started getty@tty1.service - Getty on tty1.
60.997 [  OK  ] Started getty@tty2.service - Getty on tty2.
60.997 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
61.040 [  OK  ] Started getty@tty3.service - Getty on tty3.
61.083 [  OK  ] Started getty@tty4.service - Getty on tty4.
61.104 [  OK  ] Started getty@tty5.service - Getty on tty5.
61.126 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
61.169 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
61.169 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
61.190 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
61.212 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
61.275 [  OK  ] Started getty@tty6.service - Getty on tty6.
61.275 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
61.317 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
61.317 [  OK  ] Reached target getty.target - Login Prompts.
61.317 [  OK  ] Reached target multi-user.target - Multi-User System.
61.338 [  OK  ] Reached target graphical.target - Graphical Interface.
61.381          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
61.422 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
