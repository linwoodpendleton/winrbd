# tailts start epoch=1795467425.895
0.169 iPXE initialising devices...
0.635 
0.635 
0.635 
0.635 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.678 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.678 WRRUN-STUB
3.785 Configuring (net0 52:54:00:77:11:4a)...... ok
3.807 tftp://10.0.2.2/autoexec.ipxe... ok
3.807 WRRUN-BEGIN row=B3
3.850 Waiting for link-up on net1... ok
3.872 WRRUN-NET-OK
3.936 WRRUN-SAN-START sanboot
3.979 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.001 rbd: core stack high-water 512 of 16384 bytes
4.001 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.022 rbd: core stack high-water 760 of 16384 bytes
4.045 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.111 rbd: core stack high-water 1304 of 16384 bytes
4.154 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.175 rbd: core stack high-water 1588 of 16384 bytes
5.112 Registered SAN device 0x80
5.133 Booting from SAN device 0x80
5.196 rbd: stack high-water 2672 of 4096 bytes (1424 left)
5.217 rbd: core stack high-water 1696 of 16384 bytes
85.890 GNU GRUB  version 2.14
85.890 
85.913 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
85.913       Press enter to boot the selected OS, `e' to edit the commands       
94.099       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: stack high-water 2824 of 4096 bytes (1272 left)
94.120 rbd: core stack high-water 1696 of 16384 bytes
372.360 Loading, please wait...
372.448 Starting systemd-udevd version 255.4-1ubuntu8.19
373.294 Begin: Loading essential drivers ... done.
373.294 Begin: Running /scripts/init-premount ... done.
373.336 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
373.358 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
373.654 RBFT-HOOK table found by source scan
373.654 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
373.677 RBFT-HOOK nic: eth1 address 10.77.0.74/24
373.677 RBFT-HOOK table check (source scan):
374.063 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
374.063 RBFT PASS signature: rBFT
374.063 RBFT PASS length: 234 bytes
374.063 RBFT PASS acpi_revision: 1
374.063 RBFT PASS checksum: all 234 bytes sum to 0
374.063 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
374.063 RBFT PASS magic: WRBT
374.063 RBFT PASS version: 1
374.063 RBFT PASS header_len: 116
374.086 RBFT PASS reserved: all reserved bytes are zero
374.086 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
374.086 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
374.086 RBFT PASS namespace: absent (as in version 1)
374.086 RBFT PASS rules: every rule of the field table holds
374.086 RBFT PASS entity: wrtest-p2-b3
374.086 RBFT PASS pool: winrbd
374.086 RBFT PASS image: wrtest-p2-b3
374.086 RBFT PASS image_id: 39648e0b332d
374.086 RBFT PASS snapshot: absent, as expected
374.086 RBFT PASS auth: cephx
374.086 RBFT PASS msgr_mode: crc
374.086 RBFT PASS flags: key,static (0x6)
374.086 RBFT PASS flag_readonly: clear
374.109 RBFT PASS flag_key: set
374.109 RBFT PASS flag_nic_static: set
374.109 RBFT PASS flag_vlan: clear
374.131 RBFT PASS flag_fsid: clear
374.175 RBFT PASS flag_secure_required: clear
374.175 RBFT PASS key_type: aes
374.175 RBFT PASS key_len: 16
374.175 RBFT INFO key: present in the table (aes, 16 bytes), not printed
374.175 RBFT PASS mon_count: 1
374.175 RBFT PASS mon0: 10.77.0.10:3300
374.175 RBFT PASS fsid: none, as expected
374.175 RBFT PASS nic_mac: 52:54:00:77:12:ca
374.175 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
374.198 RBFT PASS nic_vlan: 0
374.198 RBFT PASS nic_mtu: 1500
374.198 RBFT PASS nic_family: 4
374.198 RBFT PASS nic_ip: 10.77.0.74
374.198 RBFT PASS nic_prefix: 24
374.198 RBFT PASS nic_gateway: zero, as expected
374.198 RBFT PASS nic_dns: zero, as expected
374.221 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
374.221 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
374.221 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
374.221 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
374.221 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
374.221 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
374.245 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
374.245 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
374.245 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
374.245 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
374.245 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
374.245 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
374.267 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
374.267 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
374.267 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
374.267 RBFT-RESULT PASS pass=40 fail=0 skip=0
374.267 WRBOOT-TABLE PASS
374.380 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
374.532 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
374.532 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
374.532 done.
374.532 Begin: Running /scripts/local-premount ... done.
455.788 Warning: fsck not present, so skipping root file system
455.989 done.
456.074 Begin: Running /scripts/local-bottom ... done.
456.095 Begin: Running /scripts/init-bottom ... done.
459.910 
459.910 Welcome to Ubuntu 24.04 LTS!
459.910 
462.674 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
462.695 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
462.695 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
462.695 [  OK  ] Created slice user.slice - User and Session Slice.
462.718 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
462.718 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
462.718 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
462.739          Expecting device dev-ttyS0.device - /dev/ttyS0...
462.739 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
462.739 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
462.761 [  OK  ] Reached target paths.target - Path Units.
462.761 [  OK  ] Reached target remote-fs.target - Remote File Systems.
462.783 [  OK  ] Reached target slices.target - Slice Units.
462.783 [  OK  ] Reached target swap.target - Swaps.
462.806 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
462.806 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
462.831 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
462.831 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
462.853 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
462.853 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
462.901          Mounting dev-hugepages.mount - Huge Pages File System...
462.947          Mounting dev-mqueue.mount - POSIX Message Queue File System...
462.970          Mounting sys-kernel-debug.mount - Kernel Debug File System...
463.018          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
463.063          Starting systemd-journald.service - Journal Service...
463.117          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
463.160          Starting modprobe@configfs.service - Load Kernel Module configfs...
463.203          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
463.225          Starting modprobe@drm.service - Load Kernel Module drm...
463.247          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
463.290          Starting modprobe@fuse.service - Load Kernel Module fuse...
463.313          Starting modprobe@loop.service - Load Kernel Module loop...
463.429          Starting systemd-modules-load.service - Load Kernel Modules...
463.475          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
463.520          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
463.542 [  OK  ] Started systemd-journald.service - Journal Service.
463.565 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
463.565 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
463.587 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
463.608 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
463.630 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
463.652 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
463.652 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
463.696 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
463.786 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
463.811 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
463.836 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
463.859 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
463.932 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
463.979          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
464.022          Mounting sys-kernel-config.mount - Kernel Configuration File System...
464.110          Starting systemd-random-seed.service - Load/Save OS Random Seed...
464.155          Starting systemd-sysctl.service - Apply Kernel Variables...
464.155          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
464.219 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
464.219 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
464.264 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
464.578 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
464.600 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
464.817 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
464.839          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
464.951 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
464.951 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
464.974          Mounting tmp.mount - /tmp...
465.020          Mounting var-cache.mount - /var/cache...
465.067          Mounting var-log.mount - /var/log...
465.115          Mounting var-tmp.mount - /var/tmp...
465.139          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
465.162 [  OK  ] Mounted tmp.mount - /tmp.
465.185 [  OK  ] Mounted var-cache.mount - /var/cache.
465.185 [  OK  ] Mounted var-log.mount - /var/log.
465.185 [  OK  ] Mounted var-tmp.mount - /var/tmp.
465.230 [  OK  ] Reached target local-fs.target - Local File Systems.
465.276 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
465.276 [  OK  ] Reached target sockets.target - Socket Units.
465.326          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
465.461 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
465.508          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
465.771 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
465.793          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
465.926 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
466.210 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
466.232 [  OK  ] Reached target sysinit.target - System Initialization.
466.232 [  OK  ] Started apt-daily.timer - Daily apt download activities.
466.254 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
466.276 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
466.298 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
466.320 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
466.320 [  OK  ] Started motd-news.timer - Message of the Day.
466.342 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
466.342 [  OK  ] Reached target timers.target - Timer Units.
466.364 [  OK  ] Reached target basic.target - Basic System.
466.386          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
466.430          Starting getty-static.service - geâ¦bus and logind are not available...
466.587          Starting systemd-user-sessions.service - Permit User Sessions...
466.684          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
466.867 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
466.978 [  OK  ] Started getty@tty1.service - Getty on tty1.
467.023 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
467.049 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
467.327 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
467.420 [  OK  ] Started getty@tty2.service - Getty on tty2.
467.467 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
467.490 [  OK  ] Started getty@tty3.service - Getty on tty3.
467.513 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
467.513 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
467.563 [  OK  ] Started getty@tty4.service - Getty on tty4.
467.563 [  OK  ] Started getty@tty5.service - Getty on tty5.
467.649 [  OK  ] Started getty@tty6.service - Getty on tty6.
467.671 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
467.695 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
467.787 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
467.811 [  OK  ] Reached target getty.target - Login Prompts.
467.811 [  OK  ] Reached target multi-user.target - Multi-User System.
467.835 [  OK  ] Reached target graphical.target - Graphical Interface.
467.880          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
468.013 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
