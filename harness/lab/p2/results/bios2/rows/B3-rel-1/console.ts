# tailts start epoch=1795481592.204
0.084 iPXE initialising devices...
0.145 
0.145 
0.145 
0.166 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.187 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.208 WRRUN-STUB
3.327 Configuring (net0 52:54:00:77:11:4a)...... ok
3.349 tftp://10.0.2.2/autoexec.ipxe... ok
3.349 WRRUN-BEGIN row=B3
3.392 Waiting for link-up on net1... ok
3.392 WRRUN-NET-OK
3.392 WRRUN-SAN-START sanboot
3.683 Registered SAN device 0x80
3.704 Booting from SAN device 0x80
5.813 GNU GRUB  version 2.14
5.813 
5.856 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.856       Press enter to boot the selected OS, `e' to edit the commands       
14.225       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
14.269 Starting systemd-udevd version 255.4-1ubuntu8.19
14.909 Begin: Loading essential drivers ... done.
14.909 Begin: Running /scripts/init-premount ... done.
14.951 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
14.951 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
15.302 RBFT-HOOK table found by source scan
15.302 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
15.323 RBFT-HOOK nic: eth1 address 10.77.0.74/24
15.323 RBFT-HOOK table check (source scan):
15.653 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
15.674 RBFT PASS signature: rBFT
15.674 RBFT PASS length: 234 bytes
15.674 RBFT PASS acpi_revision: 1
15.674 RBFT PASS checksum: all 234 bytes sum to 0
15.674 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
15.674 RBFT PASS magic: WRBT
15.674 RBFT PASS version: 1
15.674 RBFT PASS header_len: 116
15.674 RBFT PASS reserved: all reserved bytes are zero
15.674 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
15.695 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
15.695 RBFT PASS namespace: absent (as in version 1)
15.695 RBFT PASS rules: every rule of the field table holds
15.695 RBFT PASS entity: wrtest-p2-b3
15.695 RBFT PASS pool: winrbd
15.695 RBFT PASS image: wrtest-p2-b3
15.695 RBFT PASS image_id: 3fc6592539a3
15.695 RBFT PASS snapshot: absent, as expected
15.695 RBFT PASS auth: cephx
15.695 RBFT PASS msgr_mode: crc
15.695 RBFT PASS flags: key,static (0x6)
15.716 RBFT PASS flag_readonly: clear
15.716 RBFT PASS flag_key: set
15.716 RBFT PASS flag_nic_static: set
15.716 RBFT PASS flag_vlan: clear
15.716 RBFT PASS flag_fsid: clear
15.716 RBFT PASS flag_secure_required: clear
15.716 RBFT PASS key_type: aes
15.716 RBFT PASS key_len: 16
15.716 RBFT INFO key: present in the table (aes, 16 bytes), not printed
15.716 RBFT PASS mon_count: 1
15.737 RBFT PASS mon0: 10.77.0.10:3300
15.737 RBFT PASS fsid: none, as expected
15.737 RBFT PASS nic_mac: 52:54:00:77:12:ca
15.737 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
15.737 RBFT PASS nic_vlan: 0
15.737 RBFT PASS nic_mtu: 1500
15.737 RBFT PASS nic_family: 4
15.737 RBFT PASS nic_ip: 10.77.0.74
15.737 RBFT PASS nic_prefix: 24
15.737 RBFT PASS nic_gateway: zero, as expected
15.737 RBFT PASS nic_dns: zero, as expected
15.758 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 94 46 45 4e 53 59 53
15.758 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
15.758 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
15.758 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
15.758 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
15.758 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
15.758 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
15.758 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
15.758 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
15.779 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
15.779 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
15.779 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 66 63 36 35 39 32
15.779 RBFT DUMP 00c0: 35 33 39 61 33 00 04 00 e4 0c 0a 4d 00 0a 00 00
15.779 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
15.779 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
15.779 RBFT-RESULT PASS pass=40 fail=0 skip=0
15.779 WRBOOT-TABLE PASS
15.864 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
15.946 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
15.946 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
15.946 done.
15.946 Begin: Running /scripts/local-premount ... done.
46.113 Warning: fsck not present, so skipping root file system
46.155 done.
46.198 Begin: Running /scripts/local-bottom ... done.
46.240 Begin: Running /scripts/init-bottom ... done.
47.936 
47.936 Welcome to Ubuntu 24.04 LTS!
47.936 
49.397 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
49.397 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
49.418 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
49.418 [  OK  ] Created slice user.slice - User and Session Slice.
49.418 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
49.418 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
49.439 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
49.439          Expecting device dev-ttyS0.device - /dev/ttyS0...
49.439 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
49.439 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
49.439 [  OK  ] Reached target paths.target - Path Units.
49.439 [  OK  ] Reached target remote-fs.target - Remote File Systems.
49.439 [  OK  ] Reached target slices.target - Slice Units.
49.460 [  OK  ] Reached target swap.target - Swaps.
49.460 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
49.460 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
49.460 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
49.480 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
49.480 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
49.480 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
49.522          Mounting dev-hugepages.mount - Huge Pages File System...
49.522          Mounting dev-mqueue.mount - POSIX Message Queue File System...
49.563          Mounting sys-kernel-debug.mount - Kernel Debug File System...
49.584          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
49.605          Starting systemd-journald.service - Journal Service...
49.646          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
49.688          Starting modprobe@configfs.service - Load Kernel Module configfs...
49.729          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
49.770          Starting modprobe@drm.service - Load Kernel Module drm...
49.812          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
49.833          Starting modprobe@fuse.service - Load Kernel Module fuse...
49.855          Starting modprobe@loop.service - Load Kernel Module loop...
49.898          Starting systemd-modules-load.service - Load Kernel Modules...
49.919          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
49.940          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
49.961 [  OK  ] Started systemd-journald.service - Journal Service.
49.961 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
49.982 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
50.003 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
50.003 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
50.024 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
50.045 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
50.067 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
50.088 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
50.109 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
50.130 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
50.130 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
50.151 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
50.214          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
50.235          Mounting sys-kernel-config.mount - Kernel Configuration File System...
50.256          Starting systemd-sysctl.service - Apply Kernel Variables...
50.299          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
50.341 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
50.404 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
50.425 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
50.488          Starting systemd-random-seed.service - Load/Save OS Random Seed...
50.529 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
50.571 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
50.612 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
50.654 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
50.675          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
50.696 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
50.717 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
50.738          Mounting tmp.mount - /tmp...
50.760          Mounting var-cache.mount - /var/cache...
50.781          Mounting var-log.mount - /var/log...
50.802          Mounting var-tmp.mount - /var/tmp...
50.802          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
50.824 [  OK  ] Mounted tmp.mount - /tmp.
50.824 [  OK  ] Mounted var-cache.mount - /var/cache.
50.824 [  OK  ] Mounted var-log.mount - /var/log.
50.824 [  OK  ] Mounted var-tmp.mount - /var/tmp.
50.848 [  OK  ] Reached target local-fs.target - Local File Systems.
50.848 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
50.848 [  OK  ] Reached target sockets.target - Socket Units.
50.868          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
50.911 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
50.932          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
51.017 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
51.038          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
51.080 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
51.165 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
51.165 [  OK  ] Reached target sysinit.target - System Initialization.
51.165 [  OK  ] Started apt-daily.timer - Daily apt download activities.
51.187 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
51.187 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
51.187 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
51.187 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
51.187 [  OK  ] Started motd-news.timer - Message of the Day.
51.208 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
51.208 [  OK  ] Reached target timers.target - Timer Units.
51.208 [  OK  ] Reached target basic.target - Basic System.
51.233          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
51.276          Starting getty-static.service - geâ¦bus and logind are not available...
51.319          Starting systemd-user-sessions.service - Permit User Sessions...
51.382          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
51.403 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
51.488 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
51.678 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
51.699 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
51.742 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
51.763 [  OK  ] Started getty@tty1.service - Getty on tty1.
51.806 [  OK  ] Started getty@tty2.service - Getty on tty2.
51.827 [  OK  ] Started getty@tty3.service - Getty on tty3.
51.891 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
51.891 [  OK  ] Started getty@tty4.service - Getty on tty4.
51.913 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
51.913 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
51.955 [  OK  ] Started getty@tty5.service - Getty on tty5.
51.998 [  OK  ] Started getty@tty6.service - Getty on tty6.
52.040 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
52.062 [  OK  ] Reached target getty.target - Login Prompts.
52.083 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
52.083 [  OK  ] Reached target multi-user.target - Multi-User System.
52.105 [  OK  ] Reached target graphical.target - Graphical Interface.
52.128          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
52.171 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
