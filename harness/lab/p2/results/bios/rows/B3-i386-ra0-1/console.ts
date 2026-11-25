# tailts start epoch=1795464575.313
0.104 iPXE initialising devices...
0.308 
0.308 
0.308 
0.308 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.308 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.329 WRRUN-STUB
3.448 Configuring (net0 52:54:00:77:11:4a)...... ok
3.468 tftp://10.0.2.2/autoexec.ipxe... ok
3.468 WRRUN-BEGIN row=B3
3.509 Waiting for link-up on net1... ok
3.509 WRRUN-NET-OK
3.509 WRRUN-SAN-START sanboot
3.714 Registered SAN device 0x80
3.714 Booting from SAN device 0x80
5.235 GNU GRUB  version 2.14
5.235 
5.256 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.256       Press enter to boot the selected OS, `e' to edit the commands       
33.161       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
33.182 Starting systemd-udevd version 255.4-1ubuntu8.19
33.795 Begin: Loading essential drivers ... done.
33.795 Begin: Running /scripts/init-premount ... done.
33.836 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
33.836 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
34.205 RBFT-HOOK table found by source scan
34.205 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
34.205 RBFT-HOOK nic: eth1 address 10.77.0.74/24
34.226 RBFT-HOOK table check (source scan):
34.493 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
34.493 RBFT PASS signature: rBFT
34.493 RBFT PASS length: 234 bytes
34.493 RBFT PASS acpi_revision: 1
34.493 RBFT PASS checksum: all 234 bytes sum to 0
34.493 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
34.493 RBFT PASS magic: WRBT
34.493 RBFT PASS version: 1
34.493 RBFT PASS header_len: 116
34.493 RBFT PASS reserved: all reserved bytes are zero
34.493 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
34.514 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
34.514 RBFT PASS namespace: absent (as in version 1)
34.514 RBFT PASS rules: every rule of the field table holds
34.514 RBFT PASS entity: wrtest-p2-b3
34.514 RBFT PASS pool: winrbd
34.514 RBFT PASS image: wrtest-p2-b3
34.514 RBFT PASS image_id: 39648e0b332d
34.514 RBFT PASS snapshot: absent, as expected
34.514 RBFT PASS auth: cephx
34.514 RBFT PASS msgr_mode: crc
34.514 RBFT PASS flags: key,static (0x6)
34.514 RBFT PASS flag_readonly: clear
34.514 RBFT PASS flag_key: set
34.514 RBFT PASS flag_nic_static: set
34.514 RBFT PASS flag_vlan: clear
34.514 RBFT PASS flag_fsid: clear
34.514 RBFT PASS flag_secure_required: clear
34.514 RBFT PASS key_type: aes
34.514 RBFT PASS key_len: 16
34.535 RBFT INFO key: present in the table (aes, 16 bytes), not printed
34.535 RBFT PASS mon_count: 1
34.535 RBFT PASS mon0: 10.77.0.10:3300
34.535 RBFT PASS fsid: none, as expected
34.535 RBFT PASS nic_mac: 52:54:00:77:12:ca
34.535 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
34.535 RBFT PASS nic_vlan: 0
34.535 RBFT PASS nic_mtu: 1500
34.535 RBFT PASS nic_family: 4
34.535 RBFT PASS nic_ip: 10.77.0.74
34.535 RBFT PASS nic_prefix: 24
34.535 RBFT PASS nic_gateway: zero, as expected
34.535 RBFT PASS nic_dns: zero, as expected
34.535 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
34.535 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
34.535 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
34.535 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
34.556 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
34.556 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
34.556 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
34.556 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
34.556 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
34.556 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
34.556 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
34.556 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
34.556 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
34.556 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
34.556 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
34.556 RBFT-RESULT PASS pass=40 fail=0 skip=0
34.556 WRBOOT-TABLE PASS
34.638 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
34.721 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
34.721 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
34.721 done.
34.721 Begin: Running /scripts/local-premount ... done.
64.811 Warning: fsck not present, so skipping root file system
64.832 done.
65.002 Begin: Running /scripts/local-bottom ... done.
65.150 Begin: Running /scripts/init-bottom ... done.
68.128 
68.128 Welcome to Ubuntu 24.04 LTS!
68.128 
69.832 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
69.832 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
69.853 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
69.853 [  OK  ] Created slice user.slice - User and Session Slice.
69.853 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
69.853 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
69.853 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
69.874          Expecting device dev-ttyS0.device - /dev/ttyS0...
69.874 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
69.874 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
69.874 [  OK  ] Reached target paths.target - Path Units.
69.874 [  OK  ] Reached target remote-fs.target - Remote File Systems.
70.100 [  OK  ] Reached target slices.target - Slice Units.
70.100 [  OK  ] Reached target swap.target - Swaps.
70.100 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
70.120 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
70.120 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
70.120 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
70.247 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
70.268 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
70.305          Mounting dev-hugepages.mount - Huge Pages File System...
70.326          Mounting dev-mqueue.mount - POSIX Message Queue File System...
70.326          Mounting sys-kernel-debug.mount - Kernel Debug File System...
70.326          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
70.368          Starting systemd-journald.service - Journal Service...
70.388          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
70.388          Starting modprobe@configfs.service - Load Kernel Module configfs...
70.409          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
70.430          Starting modprobe@drm.service - Load Kernel Module drm...
70.430          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
70.450          Starting modprobe@fuse.service - Load Kernel Module fuse...
70.471          Starting modprobe@loop.service - Load Kernel Module loop...
70.491          Starting systemd-modules-load.service - Load Kernel Modules...
70.512          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
70.533          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
70.533 [  OK  ] Started systemd-journald.service - Journal Service.
70.553 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
70.553 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
70.574 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
70.574 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
70.595 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
70.595 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
70.595 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
70.616 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
70.616 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
70.636 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
70.636 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
70.636 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
70.678          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
70.698          Mounting sys-kernel-config.mount - Kernel Configuration File System...
70.719          Starting systemd-sysctl.service - Apply Kernel Variables...
70.719          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
70.740 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
70.740 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
70.740 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
70.781          Starting systemd-random-seed.service - Load/Save OS Random Seed...
70.843 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
70.864 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
71.220 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
71.241 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
71.261          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
71.282 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
71.282 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
71.428          Mounting tmp.mount - /tmp...
71.449          Mounting var-cache.mount - /var/cache...
71.469          Mounting var-log.mount - /var/log...
71.511          Mounting var-tmp.mount - /var/tmp...
71.511          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
71.532 [  OK  ] Mounted tmp.mount - /tmp.
71.532 [  OK  ] Mounted var-cache.mount - /var/cache.
71.532 [  OK  ] Mounted var-log.mount - /var/log.
71.532 [  OK  ] Mounted var-tmp.mount - /var/tmp.
71.532 [  OK  ] Reached target local-fs.target - Local File Systems.
71.552 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
71.552 [  OK  ] Reached target sockets.target - Socket Units.
71.573          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
71.593 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
71.614          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
71.676 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
71.696          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
71.737 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
72.148 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
72.169 [  OK  ] Reached target sysinit.target - System Initialization.
72.169 [  OK  ] Started apt-daily.timer - Daily apt download activities.
72.169 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
72.169 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
72.189 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
72.189 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
72.189 [  OK  ] Started motd-news.timer - Message of the Day.
72.210 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
72.210 [  OK  ] Reached target timers.target - Timer Units.
72.210 [  OK  ] Reached target basic.target - Basic System.
72.231          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
72.251          Starting getty-static.service - geâ¦bus and logind are not available...
72.251          Starting systemd-user-sessions.service - Permit User Sessions...
72.272          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
72.334 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
72.355 [  OK  ] Started getty@tty1.service - Getty on tty1.
72.375 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
72.417 [  OK  ] Started getty@tty2.service - Getty on tty2.
72.417 [  OK  ] Started getty@tty3.service - Getty on tty3.
72.458 [  OK  ] Started getty@tty4.service - Getty on tty4.
72.643 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
72.726 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
72.746 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
72.746 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
72.746 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
72.767 [  OK  ] Started getty@tty5.service - Getty on tty5.
72.787 [  OK  ] Started getty@tty6.service - Getty on tty6.
72.808 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
72.808 [  OK  ] Reached target getty.target - Login Prompts.
72.808 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
72.849 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
72.953 [  OK  ] Reached target multi-user.target - Multi-User System.
73.056 [  OK  ] Reached target graphical.target - Graphical Interface.
73.118          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
