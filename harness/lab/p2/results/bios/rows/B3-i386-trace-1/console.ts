# tailts start epoch=1795467040.255
0.784 iPXE initialising devices...
1.016 
1.016 
1.016 
1.167 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
1.210 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
1.210 WRRUN-STUB
4.276 Configuring (net0 52:54:00:77:11:4a)...... ok
4.300 tftp://10.0.2.2/autoexec.ipxe... ok
4.300 WRRUN-BEGIN row=B3
4.321 Waiting for link-up on net1... ok
4.321 WRRUN-NET-OK
4.342 WRRUN-SAN-START sanboot
4.383 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.404 rbd: core stack high-water 512 of 16384 bytes
4.426 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.426 rbd: core stack high-water 760 of 16384 bytes
4.489 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.510 rbd: core stack high-water 1304 of 16384 bytes
4.552 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.573 rbd: core stack high-water 1588 of 16384 bytes
5.429 Registered SAN device 0x80
5.473 Booting from SAN device 0x80
5.540 rbd: stack high-water 2672 of 4096 bytes (1424 left)
5.583 rbd: core stack high-water 1696 of 16384 bytes
21.372 GNU GRUB  version 2.14
21.372 
21.463 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
21.486       Press enter to boot the selected OS, `e' to edit the commands       
33.343       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: stack high-water 2824 of 4096 bytes (1272 left)
33.407 rbd: core stack high-water 1696 of 16384 bytes
248.316 Loading, please wait...
248.379 Starting systemd-udevd version 255.4-1ubuntu8.19
249.194 Begin: Loading essential drivers ... done.
249.215 Begin: Running /scripts/init-premount ... done.
249.237 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
249.258 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
249.696 RBFT-HOOK table found by source scan
249.696 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
249.717 RBFT-HOOK nic: eth1 address 10.77.0.74/24
249.717 RBFT-HOOK table check (source scan):
250.033 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
250.033 RBFT PASS signature: rBFT
250.033 RBFT PASS length: 234 bytes
250.033 RBFT PASS acpi_revision: 1
250.033 RBFT PASS checksum: all 234 bytes sum to 0
250.033 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
250.054 RBFT PASS magic: WRBT
250.054 RBFT PASS version: 1
250.054 RBFT PASS header_len: 116
250.054 RBFT PASS reserved: all reserved bytes are zero
250.054 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
250.054 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
250.054 RBFT PASS namespace: absent (as in version 1)
250.054 RBFT PASS rules: every rule of the field table holds
250.054 RBFT PASS entity: wrtest-p2-b3
250.054 RBFT PASS pool: winrbd
250.054 RBFT PASS image: wrtest-p2-b3
250.054 RBFT PASS image_id: 39648e0b332d
250.054 RBFT PASS snapshot: absent, as expected
250.054 RBFT PASS auth: cephx
250.054 RBFT PASS msgr_mode: crc
250.054 RBFT PASS flags: key,static (0x6)
250.076 RBFT PASS flag_readonly: clear
250.076 RBFT PASS flag_key: set
250.076 RBFT PASS flag_nic_static: set
250.076 RBFT PASS flag_vlan: clear
250.076 RBFT PASS flag_fsid: clear
250.076 RBFT PASS flag_secure_required: clear
250.076 RBFT PASS key_type: aes
250.076 RBFT PASS key_len: 16
250.076 RBFT INFO key: present in the table (aes, 16 bytes), not printed
250.076 RBFT PASS mon_count: 1
250.076 RBFT PASS mon0: 10.77.0.10:3300
250.076 RBFT PASS fsid: none, as expected
250.076 RBFT PASS nic_mac: 52:54:00:77:12:ca
250.076 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
250.076 RBFT PASS nic_vlan: 0
250.076 RBFT PASS nic_mtu: 1500
250.076 RBFT PASS nic_family: 4
250.076 RBFT PASS nic_ip: 10.77.0.74
250.097 RBFT PASS nic_prefix: 24
250.097 RBFT PASS nic_gateway: zero, as expected
250.097 RBFT PASS nic_dns: zero, as expected
250.097 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
250.097 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
250.097 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
250.097 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
250.097 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
250.097 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
250.097 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
250.097 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
250.118 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
250.118 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
250.118 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
250.118 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
250.118 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
250.118 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
250.118 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
250.118 RBFT-RESULT PASS pass=40 fail=0 skip=0
250.118 WRBOOT-TABLE PASS
250.201 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
250.306 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
250.306 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
250.306 done.
250.306 Begin: Running /scripts/local-premount ... done.
280.479 Warning: fsck not present, so skipping root file system
280.522 done.
280.564 Begin: Running /scripts/local-bottom ... done.
280.585 Begin: Running /scripts/init-bottom ... done.
285.198 
285.198 Welcome to Ubuntu 24.04 LTS!
285.198 
290.401 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
290.401 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
290.423 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
290.423 [  OK  ] Created slice user.slice - User and Session Slice.
290.423 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
290.423 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
290.445 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
290.445          Expecting device dev-ttyS0.device - /dev/ttyS0...
290.445 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
290.445 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
290.445 [  OK  ] Reached target paths.target - Path Units.
290.445 [  OK  ] Reached target remote-fs.target - Remote File Systems.
290.445 [  OK  ] Reached target slices.target - Slice Units.
290.467 [  OK  ] Reached target swap.target - Swaps.
290.467 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
290.467 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
290.467 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
290.467 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
290.490 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
290.490 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
290.512          Mounting dev-hugepages.mount - Huge Pages File System...
290.534          Mounting dev-mqueue.mount - POSIX Message Queue File System...
290.555          Mounting sys-kernel-debug.mount - Kernel Debug File System...
290.577          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
290.599          Starting systemd-journald.service - Journal Service...
290.726          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
291.230          Starting modprobe@configfs.service - Load Kernel Module configfs...
291.576          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
291.621          Starting modprobe@drm.service - Load Kernel Module drm...
292.156          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
292.224          Starting modprobe@fuse.service - Load Kernel Module fuse...
292.423          Starting modprobe@loop.service - Load Kernel Module loop...
292.469          Starting systemd-modules-load.service - Load Kernel Modules...
292.534          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
292.556          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
292.599 [  OK  ] Started systemd-journald.service - Journal Service.
292.620 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
292.620 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
292.620 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
292.642 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
292.642 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
293.152 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
293.174 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
293.311 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
293.460 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
293.483 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
293.527 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
293.570 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
293.612          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
293.969          Mounting sys-kernel-config.mount - Kernel Configuration File System...
294.365          Starting systemd-sysctl.service - Apply Kernel Variables...
294.411          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
294.433 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
294.455 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
294.455 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
294.519          Starting systemd-random-seed.service - Load/Save OS Random Seed...
294.603 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
294.624 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
295.035 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
295.057 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
295.079          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
295.100 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
295.121 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
295.121          Mounting tmp.mount - /tmp...
295.142          Mounting var-cache.mount - /var/cache...
295.164          Mounting var-log.mount - /var/log...
295.185          Mounting var-tmp.mount - /var/tmp...
295.206          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
295.206 [  OK  ] Mounted tmp.mount - /tmp.
295.228 [  OK  ] Mounted var-cache.mount - /var/cache.
295.228 [  OK  ] Mounted var-log.mount - /var/log.
295.228 [  OK  ] Mounted var-tmp.mount - /var/tmp.
295.228 [  OK  ] Reached target local-fs.target - Local File Systems.
295.249 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
295.249 [  OK  ] Reached target sockets.target - Socket Units.
295.292          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
295.355 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
295.355          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
295.459 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
295.480          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
295.543 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
296.267 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
296.267 [  OK  ] Reached target sysinit.target - System Initialization.
296.267 [  OK  ] Started apt-daily.timer - Daily apt download activities.
296.267 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
296.288 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
296.309 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
296.309 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
296.309 [  OK  ] Started motd-news.timer - Message of the Day.
296.309 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
296.309 [  OK  ] Reached target timers.target - Timer Units.
296.331 [  OK  ] Reached target basic.target - Basic System.
296.352          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
296.395          Starting getty-static.service - geâ¦bus and logind are not available...
296.417          Starting systemd-user-sessions.service - Permit User Sessions...
296.458          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
296.522 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
296.565 [  OK  ] Started getty@tty1.service - Getty on tty1.
296.629 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
297.401 [  OK  ] Started getty@tty2.service - Getty on tty2.
297.444 [  OK  ] Started getty@tty3.service - Getty on tty3.
297.465 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
297.569 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
297.569 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
297.590 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
297.611 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
297.611 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
297.611 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
297.633 [  OK  ] Started getty@tty4.service - Getty on tty4.
297.988 [  OK  ] Started getty@tty5.service - Getty on tty5.
298.010 [  OK  ] Started getty@tty6.service - Getty on tty6.
298.032 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
298.032 [  OK  ] Reached target getty.target - Login Prompts.
298.054 [  OK  ] Reached target multi-user.target - Multi-User System.
298.075 [  OK  ] Reached target graphical.target - Graphical Interface.
298.201          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
298.243 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
