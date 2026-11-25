# tailts start epoch=1795464315.112
0.021 iPXE initialising devices...
0.246 
0.246 
0.246 
0.246 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.268 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.268 WRRUN-STUB
3.398 Configuring (net0 52:54:00:77:11:4a)...... ok
3.398 tftp://10.0.2.2/autoexec.ipxe... ok
3.398 WRRUN-BEGIN row=B3
3.439 Waiting for link-up on net1... ok
3.439 WRRUN-NET-OK
3.439 WRRUN-SAN-START sanboot
3.460 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.480 rbd: core stack high-water 512 of 16384 bytes
3.480 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.501 rbd: core stack high-water 760 of 16384 bytes
3.522 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.542 rbd: core stack high-water 1304 of 16384 bytes
3.563 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.604 rbd: core stack high-water 1588 of 16384 bytes
3.872 Registered SAN device 0x80
3.892 Booting from SAN device 0x80
3.934 rbd: stack high-water 2676 of 4096 bytes (1420 left)
3.954 rbd: core stack high-water 1696 of 16384 bytes
5.645 GNU GRUB  version 2.14
5.645 
5.666 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.687       Press enter to boot the selected OS, `e' to edit the commands       
16.061       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
16.081 Starting systemd-udevd version 255.4-1ubuntu8.19
16.920 Begin: Loading essential drivers ... done.
16.920 Begin: Running /scripts/init-premount ... done.
16.961 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
16.961 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
17.349 RBFT-HOOK table found by source scan
17.370 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
17.370 RBFT-HOOK nic: eth1 address 10.77.0.74/24
17.370 RBFT-HOOK table check (source scan):
17.635 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
17.635 RBFT PASS signature: rBFT
17.635 RBFT PASS length: 234 bytes
17.635 RBFT PASS acpi_revision: 1
17.656 RBFT PASS checksum: all 234 bytes sum to 0
17.656 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
17.656 RBFT PASS magic: WRBT
17.656 RBFT PASS version: 1
17.656 RBFT PASS header_len: 116
17.656 RBFT PASS reserved: all reserved bytes are zero
17.656 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
17.656 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
17.656 RBFT PASS namespace: absent (as in version 1)
17.679 RBFT PASS rules: every rule of the field table holds
17.679 RBFT PASS entity: wrtest-p2-b3
17.700 RBFT PASS pool: winrbd
17.742 RBFT PASS image: wrtest-p2-b3
17.742 RBFT PASS image_id: 39648e0b332d
17.742 RBFT PASS snapshot: absent, as expected
17.742 RBFT PASS auth: cephx
17.742 RBFT PASS msgr_mode: crc
17.742 RBFT PASS flags: key,static (0x6)
17.742 RBFT PASS flag_readonly: clear
17.742 RBFT PASS flag_key: set
17.742 RBFT PASS flag_nic_static: set
17.742 RBFT PASS flag_vlan: clear
17.742 RBFT PASS flag_fsid: clear
17.763 RBFT PASS flag_secure_required: clear
17.763 RBFT PASS key_type: aes
17.763 RBFT PASS key_len: 16
17.763 RBFT INFO key: present in the table (aes, 16 bytes), not printed
17.763 RBFT PASS mon_count: 1
17.763 RBFT PASS mon0: 10.77.0.10:3300
17.763 RBFT PASS fsid: none, as expected
17.763 RBFT PASS nic_mac: 52:54:00:77:12:ca
17.763 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
17.763 RBFT PASS nic_vlan: 0
17.763 RBFT PASS nic_mtu: 1500
17.763 RBFT PASS nic_family: 4
17.763 RBFT PASS nic_ip: 10.77.0.74
17.763 RBFT PASS nic_prefix: 24
17.763 RBFT PASS nic_gateway: zero, as expected
17.784 RBFT PASS nic_dns: zero, as expected
17.784 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
17.784 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
17.784 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
17.784 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
17.784 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
17.784 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
17.784 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.784 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
17.804 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
17.804 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
17.804 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
17.804 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
17.804 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
17.804 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
17.804 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
17.804 RBFT-RESULT PASS pass=40 fail=0 skip=0
17.804 WRBOOT-TABLE PASS
17.866 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
17.948 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
17.948 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
17.948 done.
17.948 Begin: Running /scripts/local-premount ... done.
48.070 Warning: fsck not present, so skipping root file system
48.091 done.
48.132 Begin: Running /scripts/local-bottom ... done.
48.152 Begin: Running /scripts/init-bottom ... done.
49.566 
49.566 Welcome to Ubuntu 24.04 LTS!
49.566 
51.080 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
51.080 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
51.101 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
51.101 [  OK  ] Created slice user.slice - User and Session Slice.
51.101 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
51.101 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
51.101 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
51.122          Expecting device dev-ttyS0.device - /dev/ttyS0...
51.122 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
51.122 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
51.122 [  OK  ] Reached target paths.target - Path Units.
51.122 [  OK  ] Reached target remote-fs.target - Remote File Systems.
51.122 [  OK  ] Reached target slices.target - Slice Units.
51.122 [  OK  ] Reached target swap.target - Swaps.
51.143 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
51.143 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
51.143 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
51.143 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
51.163 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
51.163 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
51.184          Mounting dev-hugepages.mount - Huge Pages File System...
51.184          Mounting dev-mqueue.mount - POSIX Message Queue File System...
51.204          Mounting sys-kernel-debug.mount - Kernel Debug File System...
51.204          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
51.225          Starting systemd-journald.service - Journal Service...
51.225          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
51.246          Starting modprobe@configfs.service - Load Kernel Module configfs...
51.267          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
51.287          Starting modprobe@drm.service - Load Kernel Module drm...
51.287          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
51.308          Starting modprobe@fuse.service - Load Kernel Module fuse...
51.328          Starting modprobe@loop.service - Load Kernel Module loop...
51.349          Starting systemd-modules-load.service - Load Kernel Modules...
51.349          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
51.370          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
51.390 [  OK  ] Started systemd-journald.service - Journal Service.
51.390 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
51.390 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
51.390 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
51.411 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
51.411 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
51.411 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
51.432 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
51.432 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
51.452 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
51.452 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
51.473 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
51.473 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
51.494          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
51.515          Mounting sys-kernel-config.mount - Kernel Configuration File System...
51.535          Starting systemd-sysctl.service - Apply Kernel Variables...
51.556          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
51.556 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
51.556 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
51.577 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
51.597          Starting systemd-random-seed.service - Load/Save OS Random Seed...
51.638 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
51.659 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
52.007 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
52.027          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
52.027 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
52.048 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
52.048 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
52.068          Mounting tmp.mount - /tmp...
52.068          Mounting var-cache.mount - /var/cache...
52.089          Mounting var-log.mount - /var/log...
52.089          Mounting var-tmp.mount - /var/tmp...
52.110          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
52.110 [  OK  ] Mounted tmp.mount - /tmp.
52.110 [  OK  ] Mounted var-cache.mount - /var/cache.
52.110 [  OK  ] Mounted var-log.mount - /var/log.
52.110 [  OK  ] Mounted var-tmp.mount - /var/tmp.
52.130 [  OK  ] Reached target local-fs.target - Local File Systems.
52.130 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
52.151 [  OK  ] Reached target sockets.target - Socket Units.
52.151          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
52.192 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
52.192          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
52.253 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
52.273          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
52.314 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
52.335 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
52.335 [  OK  ] Reached target sysinit.target - System Initialization.
52.355 [  OK  ] Started apt-daily.timer - Daily apt download activities.
52.355 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
52.355 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
52.355 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
52.355 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
52.376 [  OK  ] Started motd-news.timer - Message of the Day.
52.376 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
52.376 [  OK  ] Reached target timers.target - Timer Units.
52.376 [  OK  ] Reached target basic.target - Basic System.
52.397          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
52.417          Starting getty-static.service - geâ¦bus and logind are not available...
52.417          Starting systemd-user-sessions.service - Permit User Sessions...
52.438          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
52.521 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
52.664 [  OK  ] Started getty@tty1.service - Getty on tty1.
52.973 [  OK  ] Started getty@tty2.service - Getty on tty2.
52.973 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
53.035 [  OK  ] Started getty@tty3.service - Getty on tty3.
53.055 [  OK  ] Started getty@tty4.service - Getty on tty4.
53.117 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
53.138 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
53.158 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
53.179 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
53.179 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
53.179 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
53.199 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
53.220 [  OK  ] Started getty@tty5.service - Getty on tty5.
53.241 [  OK  ] Started getty@tty6.service - Getty on tty6.
53.261 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
53.261 [  OK  ] Reached target getty.target - Login Prompts.
53.282 [  OK  ] Reached target multi-user.target - Multi-User System.
53.282 [  OK  ] Reached target graphical.target - Graphical Interface.
53.303          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
53.344 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
