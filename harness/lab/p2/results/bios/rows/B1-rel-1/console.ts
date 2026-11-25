# tailts start epoch=1795462906.935
7.797 iPXE initialising devices...
7.838 
7.838 
7.858 
7.899 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.920 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.940 WRRUN-STUB
11.102 Configuring (net0 52:54:00:77:12:c7)...... ok
11.123 tftp://10.77.0.10/autoexec.ipxe... ok
11.143 WRRUN-BEGIN row=B1
11.204 Waiting for link-up on net0... ok
11.225 WRRUN-NET-OK
11.245 WRRUN-SAN-START sanboot
11.551 Registered SAN device 0x80
11.572 Booting from SAN device 0x80
13.903 GNU GRUB  version 2.14
13.903 
13.923 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.944       Press enter to boot the selected OS, `e' to edit the commands       
26.023       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
26.044 Starting systemd-udevd version 255.4-1ubuntu8.19
26.593 Begin: Loading essential drivers ... done.
26.593 Begin: Running /scripts/init-premount ... done.
26.634 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
26.634 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
26.919 RBFT-HOOK table found by source scan
26.919 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
26.919 RBFT-HOOK nic: eth0 address 10.77.0.71/24
26.919 RBFT-HOOK table check (source scan):
27.184 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
27.184 RBFT PASS signature: rBFT
27.184 RBFT PASS length: 234 bytes
27.184 RBFT PASS acpi_revision: 1
27.184 RBFT PASS checksum: all 234 bytes sum to 0
27.205 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
27.205 RBFT PASS magic: WRBT
27.205 RBFT PASS version: 1
27.205 RBFT PASS header_len: 116
27.205 RBFT PASS reserved: all reserved bytes are zero
27.205 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
27.205 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
27.205 RBFT PASS namespace: absent (as in version 1)
27.205 RBFT PASS rules: every rule of the field table holds
27.205 RBFT PASS entity: wrtest-p2-b1
27.205 RBFT PASS pool: winrbd
27.205 RBFT PASS image: wrtest-p2-b1
27.205 RBFT PASS image_id: 38d9a2e0bcec
27.205 RBFT PASS snapshot: absent, as expected
27.205 RBFT PASS auth: cephx
27.205 RBFT PASS msgr_mode: crc
27.205 RBFT PASS flags: key,static (0x6)
27.205 RBFT PASS flag_readonly: clear
27.205 RBFT PASS flag_key: set
27.205 RBFT PASS flag_nic_static: set
27.225 RBFT PASS flag_vlan: clear
27.225 RBFT PASS flag_fsid: clear
27.225 RBFT PASS flag_secure_required: clear
27.225 RBFT PASS key_type: aes
27.225 RBFT PASS key_len: 16
27.225 RBFT INFO key: present in the table (aes, 16 bytes), not printed
27.225 RBFT PASS mon_count: 1
27.225 RBFT PASS mon0: 10.77.0.10:3300
27.225 RBFT PASS fsid: none, as expected
27.225 RBFT PASS nic_mac: 52:54:00:77:12:c7
27.225 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
27.225 RBFT PASS nic_vlan: 0
27.225 RBFT PASS nic_mtu: 1500
27.225 RBFT PASS nic_family: 4
27.225 RBFT PASS nic_ip: 10.77.0.71
27.225 RBFT PASS nic_prefix: 24
27.225 RBFT PASS nic_gateway: zero, as expected
27.225 RBFT PASS nic_dns: zero, as expected
27.225 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
27.225 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
27.246 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
27.246 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
27.246 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
27.246 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
27.246 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
27.246 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
27.246 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
27.246 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
27.246 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
27.246 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
27.246 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
27.267 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
27.267 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
27.267 RBFT-RESULT PASS pass=40 fail=0 skip=0
27.267 WRBOOT-TABLE PASS
27.308 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
27.369 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
27.369 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
27.369 done.
27.369 Begin: Running /scripts/local-premount ... done.
57.446 Warning: fsck not present, so skipping root file system
57.467 done.
57.487 Begin: Running /scripts/local-bottom ... done.
57.487 Begin: Running /scripts/init-bottom ... done.
58.242 
58.242 Welcome to Ubuntu 24.04 LTS!
58.242 
58.731 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
58.731 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
58.731 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
58.731 [  OK  ] Created slice user.slice - User and Session Slice.
58.731 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
58.731 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
58.751 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
58.751          Expecting device dev-ttyS0.device - /dev/ttyS0...
58.751 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
58.751 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
58.751 [  OK  ] Reached target paths.target - Path Units.
58.751 [  OK  ] Reached target remote-fs.target - Remote File Systems.
58.751 [  OK  ] Reached target slices.target - Slice Units.
58.751 [  OK  ] Reached target swap.target - Swaps.
58.772 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
58.772 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
58.772 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
58.772 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
58.772 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
58.792 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
58.792          Mounting dev-hugepages.mount - Huge Pages File System...
58.813          Mounting dev-mqueue.mount - POSIX Message Queue File System...
58.813          Mounting sys-kernel-debug.mount - Kernel Debug File System...
58.833          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
58.833          Starting systemd-journald.service - Journal Service...
58.854          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
58.854          Starting modprobe@configfs.service - Load Kernel Module configfs...
58.874          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
58.895          Starting modprobe@drm.service - Load Kernel Module drm...
58.895          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
58.915          Starting modprobe@fuse.service - Load Kernel Module fuse...
58.936          Starting modprobe@loop.service - Load Kernel Module loop...
58.956          Starting systemd-modules-load.service - Load Kernel Modules...
58.977          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
58.977          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
58.977 [  OK  ] Started systemd-journald.service - Journal Service.
58.997 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
58.997 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
58.997 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
58.997 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
59.018 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
59.018 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
59.018 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
59.018 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
59.039 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
59.039 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
59.039 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
59.059 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
59.059 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
59.080          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
59.100          Mounting sys-kernel-config.mount - Kernel Configuration File System...
59.121          Starting systemd-random-seed.service - Load/Save OS Random Seed...
59.142          Starting systemd-sysctl.service - Apply Kernel Variables...
59.142          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
59.162 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
59.162 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
59.162 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
59.204 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
59.265 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
59.285          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
59.285 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
59.306 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
59.306 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
59.306          Mounting tmp.mount - /tmp...
59.326          Mounting var-cache.mount - /var/cache...
59.326          Mounting var-log.mount - /var/log...
59.326          Mounting var-tmp.mount - /var/tmp...
59.347          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
59.347 [  OK  ] Mounted tmp.mount - /tmp.
59.347 [  OK  ] Mounted var-cache.mount - /var/cache.
59.368 [  OK  ] Mounted var-log.mount - /var/log.
59.368 [  OK  ] Mounted var-tmp.mount - /var/tmp.
59.368 [  OK  ] Reached target local-fs.target - Local File Systems.
59.368 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
59.388 [  OK  ] Reached target sockets.target - Socket Units.
59.388          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
59.409 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
59.429          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
59.470 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
59.470          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
59.511 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
59.511 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
59.511 [  OK  ] Reached target sysinit.target - System Initialization.
59.511 [  OK  ] Started apt-daily.timer - Daily apt download activities.
59.511 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
59.532 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
59.532 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
59.532 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
59.532 [  OK  ] Started motd-news.timer - Message of the Day.
59.532 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
59.552 [  OK  ] Reached target timers.target - Timer Units.
59.552 [  OK  ] Reached target basic.target - Basic System.
59.552          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
59.573          Starting getty-static.service - geâ¦bus and logind are not available...
59.593          Starting systemd-user-sessions.service - Permit User Sessions...
59.614          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
59.655 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
59.675 [  OK  ] Started getty@tty1.service - Getty on tty1.
59.696 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
59.737 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
59.819 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
59.819 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
59.839 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
59.839 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
59.860 [  OK  ] Started getty@tty2.service - Getty on tty2.
59.880 [  OK  ] Started getty@tty3.service - Getty on tty3.
59.901 [  OK  ] Started getty@tty4.service - Getty on tty4.
59.921 [  OK  ] Started getty@tty5.service - Getty on tty5.
59.921 [  OK  ] Started getty@tty6.service - Getty on tty6.
59.921 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
59.942 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
59.942 [  OK  ] Reached target getty.target - Login Prompts.
59.942 [  OK  ] Reached target multi-user.target - Multi-User System.
59.962 [  OK  ] Reached target graphical.target - Graphical Interface.
59.962          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
60.003 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
