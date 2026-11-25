# tailts start epoch=1795464247.483
0.000 iPXE initialising devices...
0.388 
0.388 
0.388 
0.409 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.409 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.409 WRRUN-STUB
3.532 Configuring (net0 52:54:00:77:11:4a)...... ok
3.553 tftp://10.0.2.2/autoexec.ipxe... ok
3.553 WRRUN-BEGIN row=B3
3.593 Waiting for link-up on net1... ok
3.593 WRRUN-NET-OK
3.593 WRRUN-SAN-START sanboot
3.757 Registered SAN device 0x80
3.777 Booting from SAN device 0x80
5.308 GNU GRUB  version 2.14
5.308 
5.349 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.349       Press enter to boot the selected OS, `e' to edit the commands       
12.903       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
12.923 Starting systemd-udevd version 255.4-1ubuntu8.19
13.538 Begin: Loading essential drivers ... done.
13.538 Begin: Running /scripts/init-premount ... done.
13.558 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
13.558 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
13.845 RBFT-HOOK table found by source scan
13.845 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
13.845 RBFT-HOOK nic: eth1 address 10.77.0.74/24
13.845 RBFT-HOOK table check (source scan):
14.192 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
14.192 RBFT PASS signature: rBFT
14.192 RBFT PASS length: 234 bytes
14.192 RBFT PASS acpi_revision: 1
14.192 RBFT PASS checksum: all 234 bytes sum to 0
14.192 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
14.192 RBFT PASS magic: WRBT
14.192 RBFT PASS version: 1
14.192 RBFT PASS header_len: 116
14.192 RBFT PASS reserved: all reserved bytes are zero
14.192 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
14.212 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
14.212 RBFT PASS namespace: absent (as in version 1)
14.212 RBFT PASS rules: every rule of the field table holds
14.212 RBFT PASS entity: wrtest-p2-b3
14.212 RBFT PASS pool: winrbd
14.212 RBFT PASS image: wrtest-p2-b3
14.212 RBFT PASS image_id: 39648e0b332d
14.212 RBFT PASS snapshot: absent, as expected
14.212 RBFT PASS auth: cephx
14.212 RBFT PASS msgr_mode: crc
14.212 RBFT PASS flags: key,static (0x6)
14.212 RBFT PASS flag_readonly: clear
14.212 RBFT PASS flag_key: set
14.212 RBFT PASS flag_nic_static: set
14.212 RBFT PASS flag_vlan: clear
14.212 RBFT PASS flag_fsid: clear
14.212 RBFT PASS flag_secure_required: clear
14.212 RBFT PASS key_type: aes
14.212 RBFT PASS key_len: 16
14.233 RBFT INFO key: present in the table (aes, 16 bytes), not printed
14.233 RBFT PASS mon_count: 1
14.233 RBFT PASS mon0: 10.77.0.10:3300
14.233 RBFT PASS fsid: none, as expected
14.233 RBFT PASS nic_mac: 52:54:00:77:12:ca
14.233 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
14.233 RBFT PASS nic_vlan: 0
14.233 RBFT PASS nic_mtu: 1500
14.233 RBFT PASS nic_family: 4
14.233 RBFT PASS nic_ip: 10.77.0.74
14.233 RBFT PASS nic_prefix: 24
14.233 RBFT PASS nic_gateway: zero, as expected
14.233 RBFT PASS nic_dns: zero, as expected
14.233 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
14.233 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
14.233 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
14.255 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
14.255 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
14.255 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
14.255 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
14.255 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
14.255 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
14.276 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
14.297 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
14.317 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
14.317 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
14.338 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
14.338 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
14.338 RBFT-RESULT PASS pass=40 fail=0 skip=0
14.338 WRBOOT-TABLE PASS
14.400 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
14.482 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
14.482 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
14.482 done.
14.503 Begin: Running /scripts/local-premount ... done.
44.582 Warning: fsck not present, so skipping root file system
44.622 done.
44.643 Begin: Running /scripts/local-bottom ... done.
44.643 Begin: Running /scripts/init-bottom ... done.
45.936 
45.936 Welcome to Ubuntu 24.04 LTS!
45.936 
46.897 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
46.897 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
46.918 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
46.918 [  OK  ] Created slice user.slice - User and Session Slice.
46.918 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
46.918 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
46.918 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
46.918          Expecting device dev-ttyS0.device - /dev/ttyS0...
46.938 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
46.938 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
46.938 [  OK  ] Reached target paths.target - Path Units.
46.938 [  OK  ] Reached target remote-fs.target - Remote File Systems.
46.938 [  OK  ] Reached target slices.target - Slice Units.
46.938 [  OK  ] Reached target swap.target - Swaps.
46.959 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
46.959 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
46.959 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
46.959 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
46.979 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
46.979 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
47.000          Mounting dev-hugepages.mount - Huge Pages File System...
47.000          Mounting dev-mqueue.mount - POSIX Message Queue File System...
47.020          Mounting sys-kernel-debug.mount - Kernel Debug File System...
47.020          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
47.041          Starting systemd-journald.service - Journal Service...
47.041          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
47.062          Starting modprobe@configfs.service - Load Kernel Module configfs...
47.082          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
47.103          Starting modprobe@drm.service - Load Kernel Module drm...
47.123          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
47.123          Starting modprobe@fuse.service - Load Kernel Module fuse...
47.144          Starting modprobe@loop.service - Load Kernel Module loop...
47.185          Starting systemd-modules-load.service - Load Kernel Modules...
47.185          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
47.206          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
47.206 [  OK  ] Started systemd-journald.service - Journal Service.
47.226 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
47.226 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
47.226 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
47.247 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
47.247 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
47.247 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
47.309 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
47.329 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
47.350 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
47.350 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
47.370 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
47.370 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
47.391 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
47.411          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
47.432          Mounting sys-kernel-config.mount - Kernel Configuration File System...
47.453          Starting systemd-random-seed.service - Load/Save OS Random Seed...
47.453          Starting systemd-sysctl.service - Apply Kernel Variables...
47.473          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
47.494 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
47.514 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
47.514 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
47.555 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
47.616 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
47.637 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
47.637          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
47.657 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
47.657 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
47.678          Mounting tmp.mount - /tmp...
47.698          Mounting var-cache.mount - /var/cache...
47.698          Mounting var-log.mount - /var/log...
47.719          Mounting var-tmp.mount - /var/tmp...
47.719          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
47.719 [  OK  ] Mounted tmp.mount - /tmp.
47.739 [  OK  ] Mounted var-cache.mount - /var/cache.
47.739 [  OK  ] Mounted var-log.mount - /var/log.
47.739 [  OK  ] Mounted var-tmp.mount - /var/tmp.
47.739 [  OK  ] Reached target local-fs.target - Local File Systems.
47.760 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
47.760 [  OK  ] Reached target sockets.target - Socket Units.
47.780          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
47.801 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
47.822          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
47.863 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
47.883          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
47.904 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
47.924 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
47.924 [  OK  ] Reached target sysinit.target - System Initialization.
47.924 [  OK  ] Started apt-daily.timer - Daily apt download activities.
47.945 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
47.945 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
47.945 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
47.945 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
47.945 [  OK  ] Started motd-news.timer - Message of the Day.
47.945 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
47.945 [  OK  ] Reached target timers.target - Timer Units.
47.965 [  OK  ] Reached target basic.target - Basic System.
47.965          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
47.986          Starting getty-static.service - geâ¦bus and logind are not available...
48.027          Starting systemd-user-sessions.service - Permit User Sessions...
48.068          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
48.088 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
48.109 [  OK  ] Started getty@tty1.service - Getty on tty1.
48.130 [  OK  ] Started getty@tty2.service - Getty on tty2.
48.151 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
48.171 [  OK  ] Started getty@tty3.service - Getty on tty3.
48.192 [  OK  ] Started getty@tty4.service - Getty on tty4.
48.253 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
48.357 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
48.398 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
48.419 [  OK  ] Started getty@tty5.service - Getty on tty5.
48.419 [  OK  ] Started getty@tty6.service - Getty on tty6.
48.439 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
48.439 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
48.460 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
48.460 [  OK  ] Reached target getty.target - Login Prompts.
48.480 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
48.501 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
48.542 [  OK  ] Reached target multi-user.target - Multi-User System.
48.542 [  OK  ] Reached target graphical.target - Graphical Interface.
48.563          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
48.604 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
