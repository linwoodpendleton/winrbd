# tailts start epoch=1795481224.738
7.761 iPXE initialising devices...
7.802 
7.822 
7.822 
7.865 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.886 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.907 WRRUN-STUB
10.973 Configuring (net0 52:54:00:77:12:c7)...... ok
10.994 tftp://10.77.0.10/autoexec.ipxe... ok
11.014 WRRUN-BEGIN row=B1
11.076 Waiting for link-up on net0... ok
11.096 WRRUN-NET-OK
11.117 WRRUN-SAN-START sanboot
11.301 Registered SAN device 0x80
11.321 Booting from SAN device 0x80
13.528 GNU GRUB  version 2.14
13.528 
13.549 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.569       Press enter to boot the selected OS, `e' to edit the commands       
24.068       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
24.089 Starting systemd-udevd version 255.4-1ubuntu8.19
24.661 Begin: Loading essential drivers ... done.
24.661 Begin: Running /scripts/init-premount ... done.
24.702 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
24.702 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
24.947 RBFT-HOOK table found by source scan
24.947 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
24.967 RBFT-HOOK nic: eth0 address 10.77.0.71/24
24.967 RBFT-HOOK table check (source scan):
25.233 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
25.233 RBFT PASS signature: rBFT
25.233 RBFT PASS length: 234 bytes
25.233 RBFT PASS acpi_revision: 1
25.233 RBFT PASS checksum: all 234 bytes sum to 0
25.233 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
25.233 RBFT PASS magic: WRBT
25.233 RBFT PASS version: 1
25.254 RBFT PASS header_len: 116
25.254 RBFT PASS reserved: all reserved bytes are zero
25.254 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
25.254 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
25.254 RBFT PASS namespace: absent (as in version 1)
25.254 RBFT PASS rules: every rule of the field table holds
25.254 RBFT PASS entity: wrtest-p2-b1
25.254 RBFT PASS pool: winrbd
25.254 RBFT PASS image: wrtest-p2-b1
25.254 RBFT PASS image_id: 3fae3418fe30
25.254 RBFT PASS snapshot: absent, as expected
25.274 RBFT PASS auth: cephx
25.274 RBFT PASS msgr_mode: crc
25.274 RBFT PASS flags: key,static (0x6)
25.274 RBFT PASS flag_readonly: clear
25.274 RBFT PASS flag_key: set
25.274 RBFT PASS flag_nic_static: set
25.274 RBFT PASS flag_vlan: clear
25.274 RBFT PASS flag_fsid: clear
25.274 RBFT PASS flag_secure_required: clear
25.274 RBFT PASS key_type: aes
25.274 RBFT PASS key_len: 16
25.274 RBFT INFO key: present in the table (aes, 16 bytes), not printed
25.295 RBFT PASS mon_count: 1
25.295 RBFT PASS mon0: 10.77.0.10:3300
25.295 RBFT PASS fsid: none, as expected
25.295 RBFT PASS nic_mac: 52:54:00:77:12:c7
25.295 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
25.295 RBFT PASS nic_vlan: 0
25.295 RBFT PASS nic_mtu: 1500
25.295 RBFT PASS nic_family: 4
25.295 RBFT PASS nic_ip: 10.77.0.71
25.295 RBFT PASS nic_prefix: 24
25.295 RBFT PASS nic_gateway: zero, as expected
25.295 RBFT PASS nic_dns: zero, as expected
25.295 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
25.295 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
25.295 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
25.316 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
25.316 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
25.316 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
25.316 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
25.316 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
25.316 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
25.316 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
25.316 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
25.316 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
25.316 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
25.316 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
25.316 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
25.336 RBFT-RESULT PASS pass=40 fail=0 skip=0
25.336 WRBOOT-TABLE PASS
25.377 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
25.439 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
25.439 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
25.439 done.
25.439 Begin: Running /scripts/local-premount ... done.
55.540 Warning: fsck not present, so skipping root file system
55.561 done.
55.582 Begin: Running /scripts/local-bottom ... done.
55.603 Begin: Running /scripts/init-bottom ... done.
56.870 
56.870 Welcome to Ubuntu 24.04 LTS!
56.870 
57.523 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
57.523 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
57.544 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
57.544 [  OK  ] Created slice user.slice - User and Session Slice.
57.544 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
57.544 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
57.544 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
57.544          Expecting device dev-ttyS0.device - /dev/ttyS0...
57.564 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
57.564 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
57.564 [  OK  ] Reached target paths.target - Path Units.
57.564 [  OK  ] Reached target remote-fs.target - Remote File Systems.
57.564 [  OK  ] Reached target slices.target - Slice Units.
57.564 [  OK  ] Reached target swap.target - Swaps.
57.564 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
57.564 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
57.585 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
57.585 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
57.585 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
57.585 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
57.606          Mounting dev-hugepages.mount - Huge Pages File System...
57.606          Mounting dev-mqueue.mount - POSIX Message Queue File System...
57.626          Mounting sys-kernel-debug.mount - Kernel Debug File System...
57.626          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
57.647          Starting systemd-journald.service - Journal Service...
57.647          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
57.667          Starting modprobe@configfs.service - Load Kernel Module configfs...
57.688          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
57.709          Starting modprobe@drm.service - Load Kernel Module drm...
57.729          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
57.750          Starting modprobe@fuse.service - Load Kernel Module fuse...
57.750          Starting modprobe@loop.service - Load Kernel Module loop...
57.770          Starting systemd-modules-load.service - Load Kernel Modules...
57.791          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
57.811          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
57.811 [  OK  ] Started systemd-journald.service - Journal Service.
57.811 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
57.832 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
57.832 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
57.832 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
57.832 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
57.853 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
57.853 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
57.853 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
57.874 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
57.874 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
57.874 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
57.894 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
57.915          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
57.936          Mounting sys-kernel-config.mount - Kernel Configuration File System...
57.956          Starting systemd-sysctl.service - Apply Kernel Variables...
57.977          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
57.977 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
57.977 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
57.997 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
58.039          Starting systemd-random-seed.service - Load/Save OS Random Seed...
58.059 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
58.080 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
58.101 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
58.101          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
58.121 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
58.142 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
58.142          Mounting tmp.mount - /tmp...
58.163          Mounting var-cache.mount - /var/cache...
58.183          Mounting var-log.mount - /var/log...
58.204          Mounting var-tmp.mount - /var/tmp...
58.204          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
58.225 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
58.225 [  OK  ] Mounted tmp.mount - /tmp.
58.225 [  OK  ] Mounted var-cache.mount - /var/cache.
58.225 [  OK  ] Mounted var-log.mount - /var/log.
58.225 [  OK  ] Mounted var-tmp.mount - /var/tmp.
58.245 [  OK  ] Reached target local-fs.target - Local File Systems.
58.245 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
58.245 [  OK  ] Reached target sockets.target - Socket Units.
58.266          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
58.307 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
58.307          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
58.368 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
58.389          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
58.410 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
58.430 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
58.430 [  OK  ] Reached target sysinit.target - System Initialization.
58.430 [  OK  ] Started apt-daily.timer - Daily apt download activities.
58.430 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
58.451 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
58.451 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
58.451 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
58.451 [  OK  ] Started motd-news.timer - Message of the Day.
58.472 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
58.472 [  OK  ] Reached target timers.target - Timer Units.
58.472 [  OK  ] Reached target basic.target - Basic System.
58.492          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
58.513          Starting getty-static.service - geâ¦bus and logind are not available...
58.533          Starting systemd-user-sessions.service - Permit User Sessions...
58.554          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
58.575 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
58.596 [  OK  ] Started getty@tty1.service - Getty on tty1.
58.699 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
58.719 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
58.781 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
58.802 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
58.802 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
58.822 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
58.822 [  OK  ] Started getty@tty2.service - Getty on tty2.
58.843 [  OK  ] Started getty@tty3.service - Getty on tty3.
58.843 [  OK  ] Started getty@tty4.service - Getty on tty4.
58.864 [  OK  ] Started getty@tty5.service - Getty on tty5.
58.864 [  OK  ] Started getty@tty6.service - Getty on tty6.
58.905 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
58.925 [  OK  ] Reached target getty.target - Login Prompts.
58.925 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
58.925 [  OK  ] Reached target multi-user.target - Multi-User System.
58.946 [  OK  ] Reached target graphical.target - Graphical Interface.
58.946          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
58.987 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
