# tailts start epoch=1795467450.738
0.583 iPXE initialising devices...
0.876 
0.876 
0.876 
0.897 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.939 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.939 WRRUN-STUB
4.087 Configuring (net0 52:54:00:77:11:57)...... ok
4.087 tftp://10.0.2.2/autoexec.ipxe... ok
4.108 WRRUN-BEGIN row=B3
4.191 Waiting for link-up on net1... ok
4.191 WRRUN-NET-OK
4.191 WRRUN-SAN-START sanboot
4.275 rbd: stack monitor: the stack is not iPXE's own (frame 0x7ffd5628, internal stack 0xffffffffeb54ceb0 to 0xffffffffeb54eeb0): not painted
5.210 Registered SAN device 0x80
5.231 Booting from SAN device 0x80
6.575 rbd: stack monitor: the stack is not iPXE's own (frame 0x7ffd52a8, internal stack 0xffffffffeb54ceb0 to 0xffffffffeb54eeb0): not painted
13.045 GNU GRUB  version 2.14
13.045 
13.066 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.087       Press enter to boot the selected OS, `e' to edit the commands       
405.156       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: operation timed out (WR_E_TIMEOUT)
406.350 rbd: stack monitor: the stack is not iPXE's own (frame 0x7ffd51e8, internal stack 0xffffffffeb54ceb0 to 0xffffffffeb54eeb0): not painted
469.242 Loading, please wait...
469.309 Starting systemd-udevd version 255.4-1ubuntu8.19
469.980 Begin: Loading essential drivers ... done.
469.980 Begin: Running /scripts/init-premount ... done.
470.022 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
470.022 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
470.337 RBFT-HOOK table found by source scan
470.337 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:d7
470.337 RBFT-HOOK nic: eth1 address 10.77.0.87/24
470.337 RBFT-HOOK table check (source scan):
470.674 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
470.674 RBFT PASS signature: rBFT
470.674 RBFT PASS length: 234 bytes
470.674 RBFT PASS acpi_revision: 1
470.674 RBFT PASS checksum: all 234 bytes sum to 0
470.674 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
470.674 RBFT PASS magic: WRBT
470.696 RBFT PASS version: 1
470.696 RBFT PASS header_len: 116
470.696 RBFT PASS reserved: all reserved bytes are zero
470.696 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
470.696 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
470.696 RBFT PASS namespace: absent (as in version 1)
470.696 RBFT PASS rules: every rule of the field table holds
470.696 RBFT PASS entity: wrtest-p2-b3
470.696 RBFT PASS pool: winrbd
470.696 RBFT PASS image: wrtest-p2-b3
470.696 RBFT PASS image_id: 39648e0b332d
470.719 RBFT PASS snapshot: absent, as expected
470.719 RBFT PASS auth: cephx
470.719 RBFT PASS msgr_mode: crc
470.719 RBFT PASS flags: key,static (0x6)
470.719 RBFT PASS flag_readonly: clear
470.719 RBFT PASS flag_key: set
470.719 RBFT PASS flag_nic_static: set
470.719 RBFT PASS flag_vlan: clear
470.719 RBFT PASS flag_fsid: clear
470.719 RBFT PASS flag_secure_required: clear
470.719 RBFT PASS key_type: aes
470.719 RBFT PASS key_len: 16
470.719 RBFT INFO key: present in the table (aes, 16 bytes), not printed
470.741 RBFT PASS mon_count: 1
470.741 RBFT PASS mon0: 10.77.0.10:3300
470.741 RBFT PASS fsid: none, as expected
470.741 RBFT PASS nic_mac: 52:54:00:77:12:d7
470.741 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d7 exists in this guest
470.741 RBFT PASS nic_vlan: 0
470.741 RBFT PASS nic_mtu: 1500
470.741 RBFT PASS nic_family: 4
470.741 RBFT PASS nic_ip: 10.77.0.87
470.741 RBFT PASS nic_prefix: 24
470.763 RBFT PASS nic_gateway: zero, as expected
470.763 RBFT PASS nic_dns: zero, as expected
470.763 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 87 46 45 4e 53 59 53
470.763 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
470.763 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
470.763 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
470.763 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d7 00 00
470.786 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 57 00 00 00 00 00 00 00 00
470.786 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
470.786 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
470.786 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
470.786 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
470.808 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
470.808 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
470.808 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
470.808 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
470.808 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
470.808 RBFT-RESULT PASS pass=40 fail=0 skip=0
470.808 WRBOOT-TABLE PASS
470.936 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
471.041 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
471.041 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
471.041 done.
471.062 Begin: Running /scripts/local-premount ... done.
501.221 Warning: fsck not present, so skipping root file system
501.263 done.
501.306 Begin: Running /scripts/local-bottom ... done.
501.327 Begin: Running /scripts/init-bottom ... done.
503.435 
503.435 Welcome to Ubuntu 24.04 LTS!
503.435 
505.639 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
505.639 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
505.639 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
505.660 [  OK  ] Created slice user.slice - User and Session Slice.
505.660 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
505.660 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
505.682 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
505.682          Expecting device dev-ttyS0.device - /dev/ttyS0...
505.703 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
505.703 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
505.703 [  OK  ] Reached target paths.target - Path Units.
505.703 [  OK  ] Reached target remote-fs.target - Remote File Systems.
505.724 [  OK  ] Reached target slices.target - Slice Units.
505.724 [  OK  ] Reached target swap.target - Swaps.
505.724 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
505.724 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
505.746 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
505.746 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
505.768 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
505.768 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
505.790          Mounting dev-hugepages.mount - Huge Pages File System...
505.811          Mounting dev-mqueue.mount - POSIX Message Queue File System...
505.833          Mounting sys-kernel-debug.mount - Kernel Debug File System...
505.854          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
505.898          Starting systemd-journald.service - Journal Service...
505.941          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
505.962          Starting modprobe@configfs.service - Load Kernel Module configfs...
505.983          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
506.026          Starting modprobe@drm.service - Load Kernel Module drm...
506.048          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
506.069          Starting modprobe@fuse.service - Load Kernel Module fuse...
506.112          Starting modprobe@loop.service - Load Kernel Module loop...
506.134          Starting systemd-modules-load.service - Load Kernel Modules...
506.155          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
506.177          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
506.199 [  OK  ] Started systemd-journald.service - Journal Service.
506.220 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
506.242 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
506.242 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
506.263 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
506.285 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
506.285 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
506.306 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
506.327 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
506.349 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
506.370 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
506.392 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
506.392 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
506.413 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
506.498          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
506.541          Mounting sys-kernel-config.mount - Kernel Configuration File System...
506.606          Starting systemd-random-seed.service - Load/Save OS Random Seed...
506.627          Starting systemd-sysctl.service - Apply Kernel Variables...
506.673          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
506.695 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
506.717 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
506.738 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
506.843 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
506.865 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
506.970 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
506.992          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
507.077 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
507.099 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
507.121          Mounting tmp.mount - /tmp...
507.143          Mounting var-cache.mount - /var/cache...
507.187          Mounting var-log.mount - /var/log...
507.210          Mounting var-tmp.mount - /var/tmp...
507.232          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
507.254 [  OK  ] Mounted tmp.mount - /tmp.
507.254 [  OK  ] Mounted var-cache.mount - /var/cache.
507.275 [  OK  ] Mounted var-log.mount - /var/log.
507.296 [  OK  ] Mounted var-tmp.mount - /var/tmp.
507.317 [  OK  ] Reached target local-fs.target - Local File Systems.
507.339 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
507.339 [  OK  ] Reached target sockets.target - Socket Units.
507.382          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
507.445 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
507.467          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
507.593 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
507.637          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
507.723 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
507.851 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
507.851 [  OK  ] Reached target sysinit.target - System Initialization.
507.872 [  OK  ] Started apt-daily.timer - Daily apt download activities.
507.872 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
507.893 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
507.893 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
507.893 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
507.893 [  OK  ] Started motd-news.timer - Message of the Day.
507.915 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
507.915 [  OK  ] Reached target timers.target - Timer Units.
507.936 [  OK  ] Reached target basic.target - Basic System.
507.936          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
507.979          Starting getty-static.service - geâ¦bus and logind are not available...
508.042          Starting systemd-user-sessions.service - Permit User Sessions...
508.064          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
508.211 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
508.319 [  OK  ] Started getty@tty1.service - Getty on tty1.
508.383 [  OK  ] Started getty@tty2.service - Getty on tty2.
508.531 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
508.595 [  OK  ] Started getty@tty3.service - Getty on tty3.
508.595 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
508.637 [  OK  ] Started getty@tty4.service - Getty on tty4.
508.681 [  OK  ] Started getty@tty5.service - Getty on tty5.
508.702 [  OK  ] Started getty@tty6.service - Getty on tty6.
508.724 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
508.788 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
508.858 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
508.879 [  OK  ] Reached target getty.target - Login Prompts.
508.901 WRBOOT-NET eth0 mac=52:54:00:77:11:57 
508.923 WRBOOT-NET eth1 mac=52:54:00:77:12:d7 10.77.0.87/24 fe80::5054:ff:fe77:12d7/64 
508.944 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
508.966 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
508.966 [  OK  ] Reached target multi-user.target - Multi-User System.
508.966 [  OK  ] Reached target graphical.target - Graphical Interface.
508.987          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
509.094 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
