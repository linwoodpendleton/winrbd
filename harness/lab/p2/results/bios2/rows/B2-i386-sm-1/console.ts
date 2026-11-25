# tailts start epoch=1795480477.621
0.103 iPXE initialising devices...
0.697 
0.697 
0.697 
0.718 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.718 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.718 WRRUN-STUB
3.809 Configuring (net0 52:54:00:77:11:49)...... ok
3.809 tftp://10.0.2.2/autoexec.ipxe... ok
3.809 WRRUN-BEGIN row=B2
3.850 Waiting for link-up on net1... ok
3.871 WRRUN-NET-OK
3.871 WRRUN-SAN-START sanboot
3.892 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.892 rbd: core stack high-water 512 of 16384 bytes
3.912 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.912 rbd: core stack high-water 760 of 16384 bytes
3.954 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.954 rbd: core stack high-water 1304 of 16384 bytes
3.954 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.974 rbd: core stack high-water 1588 of 16384 bytes
4.077 Registered SAN device 0x80
4.077 Booting from SAN device 0x80
4.097 rbd: stack high-water 2676 of 4096 bytes (1420 left)
4.118 rbd: core stack high-water 1696 of 16384 bytes
5.533 GNU GRUB  version 2.14
5.533 
5.574 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.574       Press enter to boot the selected OS, `e' to edit the commands       
17.012       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
17.033 Starting systemd-udevd version 255.4-1ubuntu8.19
17.627 Begin: Loading essential drivers ... done.
17.627 Begin: Running /scripts/init-premount ... done.
17.669 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
17.669 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
17.936 RBFT-HOOK table found by source scan
17.936 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
17.957 RBFT-HOOK nic: eth1 address 10.77.0.73/24
17.957 RBFT-HOOK table check (source scan):
18.245 RBFT INFO source: scan: found at physical address 0x9e140 (1 valid copy/copies)
18.245 RBFT PASS signature: rBFT
18.245 RBFT PASS length: 234 bytes
18.245 RBFT PASS acpi_revision: 1
18.245 RBFT PASS checksum: all 234 bytes sum to 0
18.245 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
18.245 RBFT PASS magic: WRBT
18.245 RBFT PASS version: 1
18.245 RBFT PASS header_len: 116
18.245 RBFT PASS reserved: all reserved bytes are zero
18.245 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
18.266 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
18.266 RBFT PASS namespace: absent (as in version 1)
18.266 RBFT PASS rules: every rule of the field table holds
18.266 RBFT PASS entity: wrtest-p2-b2
18.266 RBFT PASS pool: winrbd
18.266 RBFT PASS image: wrtest-p2-b2
18.266 RBFT PASS image_id: 3fba3d9c1c3f
18.266 RBFT PASS snapshot: absent, as expected
18.266 RBFT PASS auth: cephx
18.266 RBFT PASS msgr_mode: crc
18.287 RBFT PASS flags: key,static (0x6)
18.287 RBFT PASS flag_readonly: clear
18.287 RBFT PASS flag_key: set
18.287 RBFT PASS flag_nic_static: set
18.287 RBFT PASS flag_vlan: clear
18.287 RBFT PASS flag_fsid: clear
18.287 RBFT PASS flag_secure_required: clear
18.287 RBFT PASS key_type: aes
18.287 RBFT PASS key_len: 16
18.287 RBFT INFO key: present in the table (aes, 16 bytes), not printed
18.287 RBFT PASS mon_count: 1
18.287 RBFT PASS mon0: 10.77.0.10:3300
18.287 RBFT PASS fsid: none, as expected
18.287 RBFT PASS nic_mac: 52:54:00:77:12:c9
18.307 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
18.307 RBFT PASS nic_vlan: 0
18.307 RBFT PASS nic_mtu: 1500
18.307 RBFT PASS nic_family: 4
18.307 RBFT PASS nic_ip: 10.77.0.73
18.307 RBFT PASS nic_prefix: 24
18.307 RBFT PASS nic_gateway: zero, as expected
18.307 RBFT PASS nic_dns: zero, as expected
18.307 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 bb 46 45 4e 53 59 53
18.307 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
18.307 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
18.328 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
18.328 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
18.328 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
18.328 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.328 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
18.328 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
18.328 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
18.328 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
18.328 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 66 62 61 33 64 39
18.328 RBFT DUMP 00c0: 63 31 63 33 66 00 04 00 e4 0c 0a 4d 00 0a 00 00
18.349 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
18.349 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
18.349 RBFT-RESULT PASS pass=40 fail=0 skip=0
18.349 WRBOOT-TABLE PASS
18.411 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
18.473 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
18.473 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
18.473 done.
18.493 Begin: Running /scripts/local-premount ... done.
48.589 Warning: fsck not present, so skipping root file system
48.610 done.
48.631 Begin: Running /scripts/local-bottom ... done.
48.652 Begin: Running /scripts/init-bottom ... done.
49.964 
49.964 Welcome to Ubuntu 24.04 LTS!
49.964 
51.156 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
51.156 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
51.176 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
51.176 [  OK  ] Created slice user.slice - User and Session Slice.
51.176 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
51.176 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
51.176 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
51.176          Expecting device dev-ttyS0.device - /dev/ttyS0...
51.197 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
51.197 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
51.197 [  OK  ] Reached target paths.target - Path Units.
51.197 [  OK  ] Reached target remote-fs.target - Remote File Systems.
51.197 [  OK  ] Reached target slices.target - Slice Units.
51.197 [  OK  ] Reached target swap.target - Swaps.
51.197 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
51.218 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
51.218 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
51.218 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
51.218 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
51.218 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
51.238          Mounting dev-hugepages.mount - Huge Pages File System...
51.259          Mounting dev-mqueue.mount - POSIX Message Queue File System...
51.259          Mounting sys-kernel-debug.mount - Kernel Debug File System...
51.280          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
51.280          Starting systemd-journald.service - Journal Service...
51.300          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
51.321          Starting modprobe@configfs.service - Load Kernel Module configfs...
51.342          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
51.362          Starting modprobe@drm.service - Load Kernel Module drm...
51.362          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
51.383          Starting modprobe@fuse.service - Load Kernel Module fuse...
51.436          Starting modprobe@loop.service - Load Kernel Module loop...
51.456          Starting systemd-modules-load.service - Load Kernel Modules...
51.456          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
51.477          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
51.477 [  OK  ] Started systemd-journald.service - Journal Service.
51.477 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
51.477 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
51.497 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
51.497 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
51.497 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
51.497 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
51.518 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
51.518 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
51.539 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
51.559 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
51.559 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
51.583 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
51.604          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
51.624          Mounting sys-kernel-config.mount - Kernel Configuration File System...
51.624          Starting systemd-sysctl.service - Apply Kernel Variables...
51.666          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
51.666 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
51.666 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
51.686 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
51.707          Starting systemd-random-seed.service - Load/Save OS Random Seed...
51.748 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
51.769 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
51.830 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
51.851 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
51.872          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
51.892 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
51.892 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
51.892          Mounting tmp.mount - /tmp...
51.914          Mounting var-cache.mount - /var/cache...
51.914          Mounting var-log.mount - /var/log...
51.934          Mounting var-tmp.mount - /var/tmp...
51.934          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
51.955 [  OK  ] Mounted tmp.mount - /tmp.
51.955 [  OK  ] Mounted var-cache.mount - /var/cache.
51.955 [  OK  ] Mounted var-log.mount - /var/log.
51.955 [  OK  ] Mounted var-tmp.mount - /var/tmp.
51.976 [  OK  ] Reached target local-fs.target - Local File Systems.
51.976 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
51.976 [  OK  ] Reached target sockets.target - Socket Units.
51.997          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
52.017 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
52.038          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
52.079 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
52.100          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
52.141 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
52.182 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
52.182 [  OK  ] Reached target sysinit.target - System Initialization.
52.182 [  OK  ] Started apt-daily.timer - Daily apt download activities.
52.182 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
52.203 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
52.203 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
52.203 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
52.203 [  OK  ] Started motd-news.timer - Message of the Day.
52.203 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
52.203 [  OK  ] Reached target timers.target - Timer Units.
52.224 [  OK  ] Reached target basic.target - Basic System.
52.224          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
52.244          Starting getty-static.service - geâ¦bus and logind are not available...
52.265          Starting systemd-user-sessions.service - Permit User Sessions...
52.286          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
52.306 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
52.348 [  OK  ] Started getty@tty1.service - Getty on tty1.
52.389 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
52.409 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
52.430 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
52.430 WRBOOT-EDD int13_dev81 mbr_signature=-
52.498 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
52.539 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
52.621 [  OK  ] Started getty@tty2.service - Getty on tty2.
52.621 [  OK  ] Started getty@tty3.service - Getty on tty3.
52.642 [  OK  ] Started getty@tty4.service - Getty on tty4.
52.642 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
52.642 [  OK  ] Started getty@tty5.service - Getty on tty5.
52.662 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
52.662 [  OK  ] Started getty@tty6.service - Getty on tty6.
52.662 [  OK  ] Reached target getty.target - Login Prompts.
52.683 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
52.683 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
52.683 [  OK  ] Reached target multi-user.target - Multi-User System.
52.683 [  OK  ] Reached target graphical.target - Graphical Interface.
52.724          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
52.765 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
