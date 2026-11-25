# tailts start epoch=1795465205.208
7.716 iPXE initialising devices...
7.757 
7.757 
7.778 
7.798 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.839 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.839 WRRUN-STUB
10.978 Configuring (net0 52:54:00:77:12:d3)...... ok
11.018 tftp://10.77.0.10/autoexec.ipxe... ok
11.039 WRRUN-BEGIN row=B1
11.100 Waiting for link-up on net0... ok
11.121 WRRUN-NET-OK
11.141 WRRUN-SAN-START sanboot
11.630 Registered SAN device 0x80
11.651 Booting from SAN device 0x80
13.527 GNU GRUB  version 2.14
13.527 
13.548 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.548       Press enter to boot the selected OS, `e' to edit the commands       
25.178       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
25.219 Starting systemd-udevd version 255.4-1ubuntu8.19
25.789 Begin: Loading essential drivers ... done.
25.810 Begin: Running /scripts/init-premount ... done.
25.830 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
25.830 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
26.115 RBFT-HOOK table found by source scan
26.115 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:d3
26.115 RBFT-HOOK nic: eth0 address 10.77.0.83/24
26.115 RBFT-HOOK table check (source scan):
26.360 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
26.360 RBFT PASS signature: rBFT
26.381 RBFT PASS length: 218 bytes
26.381 RBFT PASS acpi_revision: 1
26.381 RBFT PASS checksum: all 218 bytes sum to 0
26.381 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
26.381 RBFT PASS magic: WRBT
26.381 RBFT PASS version: 1
26.381 RBFT PASS header_len: 116
26.381 RBFT PASS reserved: all reserved bytes are zero
26.381 RBFT PASS flags_reserved: only bits 0..5 are set (0x4)
26.381 RBFT PASS layout: canonical: strings, 1 monitor records, nothing else (66 bytes of area)
26.381 RBFT PASS namespace: absent (as in version 1)
26.381 RBFT PASS rules: every rule of the field table holds
26.381 RBFT PASS entity: wrtest-p2-b1
26.381 RBFT PASS pool: winrbd
26.381 RBFT PASS image: wrtest-p2-b1
26.402 RBFT PASS image_id: 38d9a2e0bcec
26.402 RBFT PASS snapshot: absent, as expected
26.402 RBFT PASS auth: cephx
26.402 RBFT PASS msgr_mode: crc
26.422 RBFT PASS flags: static (0x4)
26.422 RBFT PASS flag_readonly: clear
26.422 RBFT PASS flag_key: clear
26.422 RBFT PASS flag_nic_static: set
26.422 RBFT PASS flag_vlan: clear
26.422 RBFT PASS flag_fsid: clear
26.422 RBFT PASS flag_secure_required: clear
26.422 RBFT PASS key_type: none
26.422 RBFT PASS key_len: 0
26.422 RBFT INFO key: not in the table
26.422 RBFT INFO key_value: the table carries no key: the supplied one (aes, 16 bytes) will be used
26.422 RBFT PASS mon_count: 1
26.422 RBFT PASS mon0: 10.77.0.10:3300
26.422 RBFT PASS fsid: none, as expected
26.443 RBFT PASS nic_mac: 52:54:00:77:12:d3
26.443 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d3 exists in this guest
26.443 RBFT PASS nic_vlan: 0
26.443 RBFT PASS nic_mtu: 1500
26.443 RBFT PASS nic_family: 4
26.443 RBFT PASS nic_ip: 10.77.0.83
26.443 RBFT PASS nic_prefix: 24
26.443 RBFT PASS nic_gateway: zero, as expected
26.443 RBFT PASS nic_dns: zero, as expected
26.443 RBFT DUMP 0000: 72 42 46 54 da 00 00 00 01 d3 46 45 4e 53 59 53
26.443 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
26.443 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 04 00 00 00
26.443 RBFT DUMP 0030: 01 01 00 00 01 04 18 00 00 00 00 00 00 00 00 00
26.443 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d3 00 00
26.443 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 53 00 00 00 00 00 00 00 00
26.443 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.463 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.463 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
26.463 RBFT DUMP 0090: 2e 00 ff ff 00 00 00 00 77 72 74 65 73 74 2d 70
26.463 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
26.463 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
26.463 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
26.463 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00
26.463 RBFT-RESULT PASS pass=40 fail=0 skip=0
26.463 WRBOOT-TABLE PASS
26.525 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
26.627 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
26.627 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
26.627 done.
26.647 Begin: Running /scripts/local-premount ... done.
56.733 Warning: fsck not present, so skipping root file system
56.753 done.
56.794 Begin: Running /scripts/local-bottom ... done.
56.794 Begin: Running /scripts/init-bottom ... done.
57.915 
57.915 Welcome to Ubuntu 24.04 LTS!
57.915 
58.772 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
58.793 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
58.793 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
58.793 [  OK  ] Created slice user.slice - User and Session Slice.
58.793 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
58.793 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
58.813 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
58.813          Expecting device dev-ttyS0.device - /dev/ttyS0...
58.813 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
58.813 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
58.813 [  OK  ] Reached target paths.target - Path Units.
58.813 [  OK  ] Reached target remote-fs.target - Remote File Systems.
58.834 [  OK  ] Reached target slices.target - Slice Units.
58.834 [  OK  ] Reached target swap.target - Swaps.
58.834 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
58.834 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
58.834 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
58.834 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
58.854 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
58.854 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
58.854          Mounting dev-hugepages.mount - Huge Pages File System...
58.875          Mounting dev-mqueue.mount - POSIX Message Queue File System...
58.895          Mounting sys-kernel-debug.mount - Kernel Debug File System...
58.895          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
58.916          Starting systemd-journald.service - Journal Service...
58.936          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
58.936          Starting modprobe@configfs.service - Load Kernel Module configfs...
58.957          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
58.978          Starting modprobe@drm.service - Load Kernel Module drm...
58.978          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
58.998          Starting modprobe@fuse.service - Load Kernel Module fuse...
59.019          Starting modprobe@loop.service - Load Kernel Module loop...
59.039          Starting systemd-modules-load.service - Load Kernel Modules...
59.039          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
59.060          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
59.060 [  OK  ] Started systemd-journald.service - Journal Service.
59.080 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
59.080 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
59.080 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
59.101 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
59.101 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
59.101 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
59.101 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
59.122 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
59.122 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
59.142 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
59.163 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
59.163 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
59.204          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
59.204          Mounting sys-kernel-config.mount - Kernel Configuration File System...
59.224          Starting systemd-sysctl.service - Apply Kernel Variables...
59.245          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
59.245 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
59.265 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
59.265 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
59.286          Starting systemd-random-seed.service - Load/Save OS Random Seed...
59.327 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
59.327 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
59.492 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
59.513          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
59.533 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
59.554 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
59.554 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
59.574          Mounting tmp.mount - /tmp...
59.574          Mounting var-cache.mount - /var/cache...
59.615          Mounting var-log.mount - /var/log...
59.615          Mounting var-tmp.mount - /var/tmp...
59.636          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
59.636 [  OK  ] Mounted tmp.mount - /tmp.
59.636 [  OK  ] Mounted var-cache.mount - /var/cache.
59.636 [  OK  ] Mounted var-log.mount - /var/log.
59.636 [  OK  ] Mounted var-tmp.mount - /var/tmp.
59.656 [  OK  ] Reached target local-fs.target - Local File Systems.
59.656 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
59.677 [  OK  ] Reached target sockets.target - Socket Units.
59.698          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
59.718 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
59.718          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
59.780 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
59.800          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
59.821 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
59.821 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
59.841 [  OK  ] Reached target sysinit.target - System Initialization.
59.841 [  OK  ] Started apt-daily.timer - Daily apt download activities.
59.841 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
59.841 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
59.841 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
59.841 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
59.862 [  OK  ] Started motd-news.timer - Message of the Day.
59.862 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
59.862 [  OK  ] Reached target timers.target - Timer Units.
59.862 [  OK  ] Reached target basic.target - Basic System.
59.882          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
59.903          Starting getty-static.service - geâ¦bus and logind are not available...
59.944          Starting systemd-user-sessions.service - Permit User Sessions...
59.965          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
59.985 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
60.046 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
60.088 [  OK  ] Started getty@tty1.service - Getty on tty1.
60.108 [  OK  ] Started getty@tty2.service - Getty on tty2.
60.150 [  OK  ] Started getty@tty3.service - Getty on tty3.
60.170 [  OK  ] Started getty@tty4.service - Getty on tty4.
60.191 [  OK  ] Started getty@tty5.service - Getty on tty5.
60.212 WRBOOT-NET eth0 mac=52:54:00:77:12:d3 10.77.0.83/24 fe80::5054:ff:fe77:12d3/64 
60.232 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
60.232 [  OK  ] Started getty@tty6.service - Getty on tty6.
60.232 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
60.253 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
60.355 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
60.396 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
60.396 [  OK  ] Reached target getty.target - Login Prompts.
60.644 [  OK  ] Finish
