# tailts start epoch=1795464851.945
0.327 iPXE initialising devices...
0.942 
0.942 
0.942 
0.962 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.962 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.962 WRRUN-STUB
4.047 Configuring (net0 52:54:00:77:11:49)...... ok
4.068 tftp://10.0.2.2/autoexec.ipxe... ok
4.068 WRRUN-BEGIN row=B2
4.109 Waiting for link-up on net1... ok
4.109 WRRUN-NET-OK
4.109 WRRUN-SAN-START sanboot
4.129 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.150 rbd: core stack high-water 512 of 16384 bytes
4.150 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.150 rbd: core stack high-water 760 of 16384 bytes
4.191 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.212 rbd: core stack high-water 1304 of 16384 bytes
4.437 rbd: stack high-water 2096 of 4096 bytes (2000 left)
4.437 rbd: core stack high-water 1588 of 16384 bytes
5.115 Registered SAN device 0x80
5.115 Booting from SAN device 0x80
5.135 rbd: stack high-water 2676 of 4096 bytes (1420 left)
5.177 rbd: core stack high-water 1696 of 16384 bytes
7.726 GNU GRUB  version 2.14
7.726 
7.747 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
7.768       Press enter to boot the selected OS, `e' to edit the commands       
21.724       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
21.765 Starting systemd-udevd version 255.4-1ubuntu8.19
22.358 Begin: Loading essential drivers ... done.
22.379 Begin: Running /scripts/init-premount ... done.
22.399 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
22.399 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
22.829 RBFT-HOOK table found by source scan
22.849 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
22.849 RBFT-HOOK nic: eth1 address 10.77.0.73/24
22.849 RBFT-HOOK table check (source scan):
23.115 RBFT INFO source: scan: found at physical address 0x9e140 (1 valid copy/copies)
23.115 RBFT PASS signature: rBFT
23.115 RBFT PASS length: 234 bytes
23.115 RBFT PASS acpi_revision: 1
23.115 RBFT PASS checksum: all 234 bytes sum to 0
23.136 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
23.136 RBFT PASS magic: WRBT
23.136 RBFT PASS version: 1
23.136 RBFT PASS header_len: 116
23.136 RBFT PASS reserved: all reserved bytes are zero
23.136 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
23.136 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
23.136 RBFT PASS namespace: absent (as in version 1)
23.136 RBFT PASS rules: every rule of the field table holds
23.136 RBFT PASS entity: wrtest-p2-b2
23.136 RBFT PASS pool: winrbd
23.136 RBFT PASS image: wrtest-p2-b2
23.136 RBFT PASS image_id: 3956afc63637
23.136 RBFT PASS snapshot: absent, as expected
23.136 RBFT PASS auth: cephx
23.136 RBFT PASS msgr_mode: crc
23.136 RBFT PASS flags: key,static (0x6)
23.136 RBFT PASS flag_readonly: clear
23.136 RBFT PASS flag_key: set
23.136 RBFT PASS flag_nic_static: set
23.136 RBFT PASS flag_vlan: clear
23.136 RBFT PASS flag_fsid: clear
23.157 RBFT PASS flag_secure_required: clear
23.157 RBFT PASS key_type: aes
23.157 RBFT PASS key_len: 16
23.157 RBFT INFO key: present in the table (aes, 16 bytes), not printed
23.157 RBFT PASS mon_count: 1
23.157 RBFT PASS mon0: 10.77.0.10:3300
23.157 RBFT PASS fsid: none, as expected
23.157 RBFT PASS nic_mac: 52:54:00:77:12:c9
23.157 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
23.157 RBFT PASS nic_vlan: 0
23.157 RBFT PASS nic_mtu: 1500
23.157 RBFT PASS nic_family: 4
23.157 RBFT PASS nic_ip: 10.77.0.73
23.157 RBFT PASS nic_prefix: 24
23.157 RBFT PASS nic_gateway: zero, as expected
23.157 RBFT PASS nic_dns: zero, as expected
23.157 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 95 46 45 4e 53 59 53
23.157 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
23.157 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
23.178 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
23.178 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
23.178 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
23.178 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
23.178 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
23.178 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
23.178 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
23.178 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
23.178 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 39 35 36 61 66 63
23.178 RBFT DUMP 00c0: 36 33 36 33 37 00 04 00 e4 0c 0a 4d 00 0a 00 00
23.178 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
23.178 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
23.178 RBFT-RESULT PASS pass=40 fail=0 skip=0
23.178 WRBOOT-TABLE PASS
23.260 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
23.321 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
23.321 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
23.321 done.
23.321 Begin: Running /scripts/local-premount ... done.
53.746 Warning: fsck not present, so skipping root file system
53.788 done.
53.849 Begin: Running /scripts/local-bottom ... done.
53.870 Begin: Running /scripts/init-bottom ... done.
55.834 
55.834 Welcome to Ubuntu 24.04 LTS!
55.834 
57.353 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
57.353 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
57.374 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
57.374 [  OK  ] Created slice user.slice - User and Session Slice.
57.374 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
57.395 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
57.395 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
57.395          Expecting device dev-ttyS0.device - /dev/ttyS0...
57.395 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
57.395 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
57.395 [  OK  ] Reached target paths.target - Path Units.
57.416 [  OK  ] Reached target remote-fs.target - Remote File Systems.
57.416 [  OK  ] Reached target slices.target - Slice Units.
57.416 [  OK  ] Reached target swap.target - Swaps.
57.416 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
57.416 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
57.436 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
57.436 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
57.436 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
57.457 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
57.478          Mounting dev-hugepages.mount - Huge Pages File System...
57.478          Mounting dev-mqueue.mount - POSIX Message Queue File System...
57.498          Mounting sys-kernel-debug.mount - Kernel Debug File System...
57.498          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
57.519          Starting systemd-journald.service - Journal Service...
57.540          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
57.540          Starting modprobe@configfs.service - Load Kernel Module configfs...
57.561          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
57.685          Starting modprobe@drm.service - Load Kernel Module drm...
57.706          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
57.727          Starting modprobe@fuse.service - Load Kernel Module fuse...
57.748          Starting modprobe@loop.service - Load Kernel Module loop...
57.768          Starting systemd-modules-load.service - Load Kernel Modules...
57.810          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
57.810          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
57.810 [  OK  ] Started systemd-journald.service - Journal Service.
57.830 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
57.830 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
57.830 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
57.852 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
57.852 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
57.852 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
57.872 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
57.872 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
57.872 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
57.893 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
57.893 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
57.914 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
57.955          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
57.976          Mounting sys-kernel-config.mount - Kernel Configuration File System...
57.997          Starting systemd-sysctl.service - Apply Kernel Variables...
58.019          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
58.019 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
58.040 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
58.040 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
58.061          Starting systemd-random-seed.service - Load/Save OS Random Seed...
58.123 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
58.123 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
58.205 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
58.226          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
58.246 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
58.267 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
58.267          Mounting tmp.mount - /tmp...
58.288          Mounting var-cache.mount - /var/cache...
58.309          Mounting var-log.mount - /var/log...
58.309          Mounting var-tmp.mount - /var/tmp...
58.330          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
58.330 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
58.330 [  OK  ] Mounted tmp.mount - /tmp.
58.351 [  OK  ] Mounted var-cache.mount - /var/cache.
58.351 [  OK  ] Mounted var-log.mount - /var/log.
58.351 [  OK  ] Mounted var-tmp.mount - /var/tmp.
58.351 [  OK  ] Reached target local-fs.target - Local File Systems.
58.371 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
58.371 [  OK  ] Reached target sockets.target - Socket Units.
58.392          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
58.413 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
58.433          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
58.495 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
58.516          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
58.537 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
58.721 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
58.721 [  OK  ] Reached target sysinit.target - System Initialization.
58.721 [  OK  ] Started apt-daily.timer - Daily apt download activities.
58.742 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
58.742 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
58.742 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
58.742 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
58.763 [  OK  ] Started motd-news.timer - Message of the Day.
58.763 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
58.763 [  OK  ] Reached target timers.target - Timer Units.
58.763 [  OK  ] Reached target basic.target - Basic System.
58.784          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
58.825          Starting getty-static.service - geâ¦bus and logind are not available...
58.866          Starting systemd-user-sessions.service - Permit User Sessions...
58.907          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
58.928 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
59.092 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
59.113 [  OK  ] Started getty@tty1.service - Getty on tty1.
59.155 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
59.217 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
59.217 WRBOOT-EDD int13_dev81 mbr_signature=-
59.321 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
59.362 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
59.383 [  OK  ] Started getty@tty2.service - Getty on tty2.
59.403 [  OK  ] Started getty@tty3.service - Getty on tty3.
59.403 [  OK  ] Started getty@tty4.service - Getty on tty4.
59.424 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
59.424 [  OK  ] Started getty@tty5.service - Getty on tty5.
59.445 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
59.445 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
59.445 [  OK  ] Started getty@tty6.service - Getty on tty6.
59.465 [  OK  ] Reached target getty.target - Login Prompts.
59.486 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
59.486 [  OK  ] Reached target multi-user.target - Multi-User System.
59.486 [  OK  ] Reached target graphical.target - Graphical Interface.
59.506          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
59.527 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
