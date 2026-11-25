# tailts start epoch=1795465014.391
7.865 iPXE initialising devices...
7.906 
7.927 
7.947 
7.968 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.009 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.009 WRRUN-STUB
11.483 Configuring (net0 52:54:00:77:12:d1)...... ok
11.666 tftp://10.77.0.10/autoexec.ipxe... ok
11.687 WRRUN-BEGIN row=B1
11.748 Waiting for link-up on net0... ok
11.769 WRRUN-NET-OK
11.789 WRRUN-SAN-START sanboot
11.830 rbd: stack high-water 3360 of 8192 bytes (4832 left)
11.912 rbd: stack high-water 3960 of 8192 bytes (4232 left)
11.953 rbd: stack high-water 4344 of 8192 bytes (3848 left)
12.096 rbd: stack high-water 4648 of 8192 bytes (3544 left)
12.360 Registered SAN device 0x80
12.381 Booting from SAN device 0x80
12.422 rbd: stack high-water 4864 of 8192 bytes (3328 left)
13.648 rbd: stack high-water 5608 of 8192 bytes (2584 left)
14.911 GNU GRUB  version 2.14
14.911 
14.932 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.932       Press enter to boot the selected OS, `e' to edit the commands       
28.711       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
28.751 Starting systemd-udevd version 255.4-1ubuntu8.19
29.323 Begin: Loading essential drivers ... done.
29.323 Begin: Running /scripts/init-premount ... done.
29.344 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
29.344 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
29.630 RBFT-HOOK table found by source scan
29.630 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:d1
29.630 RBFT-HOOK nic: eth0 address 10.77.0.81/24
29.630 RBFT-HOOK table check (source scan):
29.875 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
29.875 RBFT PASS signature: rBFT
29.875 RBFT PASS length: 234 bytes
29.896 RBFT PASS acpi_revision: 1
29.896 RBFT PASS checksum: all 234 bytes sum to 0
29.896 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
29.896 RBFT PASS magic: WRBT
29.896 RBFT PASS version: 1
29.896 RBFT PASS header_len: 116
29.896 RBFT PASS reserved: all reserved bytes are zero
29.896 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
29.896 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
29.896 RBFT PASS namespace: absent (as in version 1)
29.896 RBFT PASS rules: every rule of the field table holds
29.896 RBFT PASS entity: wrtest-p2-b1
29.896 RBFT PASS pool: winrbd
29.896 RBFT PASS image: wrtest-p2-b1
29.896 RBFT PASS image_id: 38d9a2e0bcec
29.896 RBFT PASS snapshot: absent, as expected
29.896 RBFT PASS auth: cephx
29.896 RBFT PASS msgr_mode: crc
29.917 RBFT PASS flags: key,static (0x6)
29.917 RBFT PASS flag_readonly: clear
29.917 RBFT PASS flag_key: set
29.917 RBFT PASS flag_nic_static: set
29.917 RBFT PASS flag_vlan: clear
29.917 RBFT PASS flag_fsid: clear
29.917 RBFT PASS flag_secure_required: clear
29.917 RBFT PASS key_type: aes
29.917 RBFT PASS key_len: 16
29.917 RBFT INFO key: present in the table (aes, 16 bytes), not printed
29.917 RBFT PASS mon_count: 1
29.917 RBFT PASS mon0: 10.77.0.10:3300
29.917 RBFT PASS fsid: none, as expected
29.917 RBFT PASS nic_mac: 52:54:00:77:12:d1
29.917 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d1 exists in this guest
29.917 RBFT PASS nic_vlan: 0
29.917 RBFT PASS nic_mtu: 1500
29.917 RBFT PASS nic_family: 4
29.917 RBFT PASS nic_ip: 10.77.0.81
29.917 RBFT PASS nic_prefix: 24
29.917 RBFT PASS nic_gateway: zero, as expected
29.917 RBFT PASS nic_dns: zero, as expected
29.917 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 23 46 45 4e 53 59 53
29.937 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
29.937 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
29.937 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
29.937 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d1 00 00
29.937 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 51 00 00 00 00 00 00 00 00
29.937 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.937 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.937 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
29.937 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
29.937 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
29.937 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
29.937 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
29.958 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
29.958 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
29.958 RBFT-RESULT PASS pass=40 fail=0 skip=0
29.958 WRBOOT-TABLE PASS
29.999 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
30.080 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
30.080 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
30.080 done.
30.101 Begin: Running /scripts/local-premount ... done.
93.548 Warning: fsck not present, so skipping root file system
93.591 done.
93.653 Begin: Running /scripts/local-bottom ... done.
93.674 Begin: Running /scripts/init-bottom ... done.
103.977 
103.977 Welcome to Ubuntu 24.04 LTS!
103.977 
107.016 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
107.016 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
107.016 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
107.037 [  OK  ] Created slice user.slice - User and Session Slice.
107.037 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
107.037 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
107.058 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
107.058          Expecting device dev-ttyS0.device - /dev/ttyS0...
107.058 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
107.079 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
107.079 [  OK  ] Reached target paths.target - Path Units.
107.079 [  OK  ] Reached target remote-fs.target - Remote File Systems.
107.079 [  OK  ] Reached target slices.target - Slice Units.
107.079 [  OK  ] Reached target swap.target - Swaps.
107.079 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
107.100 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
107.100 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
107.100 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
107.120 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
107.120 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
107.141          Mounting dev-hugepages.mount - Huge Pages File System...
107.141          Mounting dev-mqueue.mount - POSIX Message Queue File System...
107.162          Mounting sys-kernel-debug.mount - Kernel Debug File System...
107.162          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
107.162          Starting systemd-journald.service - Journal Service...
107.183          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
107.618          Starting modprobe@configfs.service - Load Kernel Module configfs...
107.659          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
107.680          Starting modprobe@drm.service - Load Kernel Module drm...
107.826          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
107.847          Starting modprobe@fuse.service - Load Kernel Module fuse...
107.867          Starting modprobe@loop.service - Load Kernel Module loop...
107.950          Starting systemd-modules-load.service - Load Kernel Modules...
107.971          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
107.992          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
108.012 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
108.012 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
108.033 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
108.033 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
108.033 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
108.054 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
108.054 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
108.075 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
108.075 [  OK  ] Started systemd-journald.service - Journal Service.
108.095          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
108.116          Mounting sys-kernel-config.mount - Kernel Configuration File System...
108.137          Starting systemd-sysctl.service - Apply Kernel Variables...
108.158          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
108.693 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
108.693 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
108.714 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
108.714 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
108.714 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
108.734 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
108.734 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
108.755 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
108.797 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
108.817          Starting systemd-random-seed.service - Load/Save OS Random Seed...
108.838          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
108.838 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
108.859 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
108.859 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
108.879          Mounting tmp.mount - /tmp...
108.900          Mounting var-cache.mount - /var/cache...
108.900          Mounting var-log.mount - /var/log...
108.921          Mounting var-tmp.mount - /var/tmp...
108.942          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
108.942 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
108.942 [  OK  ] Mounted tmp.mount - /tmp.
108.942 [  OK  ] Mounted var-cache.mount - /var/cache.
108.942 [  OK  ] Mounted var-log.mount - /var/log.
108.963 [  OK  ] Mounted var-tmp.mount - /var/tmp.
108.963 [  OK  ] Reached target local-fs.target - Local File Systems.
108.983 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
108.983 [  OK  ] Reached target sockets.target - Socket Units.
109.004          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
109.025 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
109.046          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
109.108 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
109.129          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
109.150 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
109.191 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
109.191 [  OK  ] Reached target sysinit.target - System Initialization.
109.191 [  OK  ] Started apt-daily.timer - Daily apt download activities.
109.191 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
109.212 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
109.500 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
109.521 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
109.541 [  OK  ] Started motd-news.timer - Message of the Day.
109.541 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
109.562 [  OK  ] Reached target timers.target - Timer Units.
109.562 [  OK  ] Reached target basic.target - Basic System.
109.583          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
109.583          Starting getty-static.service - geâ¦bus and logind are not available...
109.604          Starting systemd-user-sessions.service - Permit User Sessions...
109.829          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
109.871 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
109.891 [  OK  ] Started getty@tty1.service - Getty on tty1.
109.933 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
109.975 [  OK  ] Started getty@tty2.service - Getty on tty2.
109.975 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
110.058 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
110.141 [  OK  ] Started getty@tty3.service - Getty on tty3.
110.162 [  OK  ] Started getty@tty4.service - Getty on tty4.
110.162 WRBOOT-NET eth0 mac=52:54:00:77:12:d1 10.77.0.81/24 fe80::5054:ff:fe77:12d1/64 
110.162 [  OK  ] Started getty@tty5.service - Getty on tty5.
110.182 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
110.203 [  OK  ] Started getty@tty6.service - Getty on tty6.
110.456 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
110.456 [  OK  ] Reached target getty.target - Login Prompts.
110.476 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
110.518 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
110.539 [  OK  ] Reached target multi-user.target - Multi-User System.
110.539 [  OK  ] Reached target graphical.target - Graphical Interface.
110.580          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
110.779 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
