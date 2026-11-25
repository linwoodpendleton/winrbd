# tailts start epoch=1795481523.167
0.249 iPXE initialising devices...
0.805 
0.805 
0.805 
0.826 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.847 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.847 WRRUN-STUB
3.992 Configuring (net0 52:54:00:77:11:49)...... ok
4.013 tftp://10.0.2.2/autoexec.ipxe... ok
4.013 WRRUN-BEGIN row=B2
4.034 Waiting for link-up on net1... ok
4.055 WRRUN-NET-OK
4.055 WRRUN-SAN-START sanboot
4.220 Registered SAN device 0x80
4.241 Booting from SAN device 0x80
5.751 GNU GRUB  version 2.14
5.751 
5.814 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.814       Press enter to boot the selected OS, `e' to edit the commands       
18.193       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
18.213 Starting systemd-udevd version 255.4-1ubuntu8.19
19.159 Begin: Loading essential drivers ... done.
19.183 Begin: Running /scripts/init-premount ... done.
19.242 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
19.242 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
20.274 RBFT-HOOK table found by source scan
20.297 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:c9
20.326 RBFT-HOOK nic: eth1 address 10.77.0.73/24
20.326 RBFT-HOOK table check (source scan):
21.121 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
21.121 RBFT PASS signature: rBFT
21.121 RBFT PASS length: 234 bytes
21.121 RBFT PASS acpi_revision: 1
21.121 RBFT PASS checksum: all 234 bytes sum to 0
21.121 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
21.121 RBFT PASS magic: WRBT
21.121 RBFT PASS version: 1
21.121 RBFT PASS header_len: 116
21.142 RBFT PASS reserved: all reserved bytes are zero
21.142 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
21.142 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
21.142 RBFT PASS namespace: absent (as in version 1)
21.142 RBFT PASS rules: every rule of the field table holds
21.163 RBFT PASS entity: wrtest-p2-b2
21.163 RBFT PASS pool: winrbd
21.163 RBFT PASS image: wrtest-p2-b2
21.163 RBFT PASS image_id: 3fba3d9c1c3f
21.163 RBFT PASS snapshot: absent, as expected
21.163 RBFT PASS auth: cephx
21.184 RBFT PASS msgr_mode: crc
21.184 RBFT PASS flags: key,static (0x6)
21.184 RBFT PASS flag_readonly: clear
21.184 RBFT PASS flag_key: set
21.184 RBFT PASS flag_nic_static: set
21.184 RBFT PASS flag_vlan: clear
21.184 RBFT PASS flag_fsid: clear
21.204 RBFT PASS flag_secure_required: clear
21.204 RBFT PASS key_type: aes
21.204 RBFT PASS key_len: 16
21.204 RBFT INFO key: present in the table (aes, 16 bytes), not printed
21.204 RBFT PASS mon_count: 1
21.204 RBFT PASS mon0: 10.77.0.10:3300
21.230 RBFT PASS fsid: none, as expected
21.230 RBFT PASS nic_mac: 52:54:00:77:12:c9
21.230 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c9 exists in this guest
21.230 RBFT PASS nic_vlan: 0
21.230 RBFT PASS nic_mtu: 1500
21.230 RBFT PASS nic_family: 4
21.257 RBFT PASS nic_ip: 10.77.0.73
21.257 RBFT PASS nic_prefix: 24
21.257 RBFT PASS nic_gateway: zero, as expected
21.257 RBFT PASS nic_dns: zero, as expected
21.257 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 bb 46 45 4e 53 59 53
21.257 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
21.278 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
21.278 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
21.278 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c9 00 00
21.278 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 49 00 00 00 00 00 00 00 00
21.278 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
21.299 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
21.299 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
21.299 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
21.299 RBFT DUMP 00a0: 32 2d 62 32 00 77 69 6e 72 62 64 00 77 72 74 65
21.322 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 32 00 33 66 62 61 33 64 39
21.322 RBFT DUMP 00c0: 63 31 63 33 66 00 04 00 e4 0c 0a 4d 00 0a 00 00
21.322 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
21.322 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
21.322 RBFT-RESULT PASS pass=40 fail=0 skip=0
21.322 WRBOOT-TABLE PASS
21.948 RBFT-HOOK map: pool winrbd image wrtest-p2-b2 via 10.77.0.10:3300 as client.wrtest-p2-b2 (options ms_mode=crc,noshare, the key is not shown)
22.635 RBFT-HOOK map: image winrbd/wrtest-p2-b2 is /dev/rbd0, root device /dev/rbd0p1
22.635 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
22.635 done.
22.666 Begin: Running /scripts/local-premount ... done.
52.805 Warning: fsck not present, so skipping root file system
52.825 done.
52.846 Begin: Running /scripts/local-bottom ... done.
52.867 Begin: Running /scripts/init-bottom ... done.
54.419 
54.419 Welcome to Ubuntu 24.04 LTS!
54.419 
55.946 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
55.946 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
55.967 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
55.967 [  OK  ] Created slice user.slice - User and Session Slice.
55.967 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
55.967 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
55.988 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
55.988          Expecting device dev-ttyS0.device - /dev/ttyS0...
55.988 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
55.988 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
55.988 [  OK  ] Reached target paths.target - Path Units.
55.988 [  OK  ] Reached target remote-fs.target - Remote File Systems.
55.988 [  OK  ] Reached target slices.target - Slice Units.
56.009 [  OK  ] Reached target swap.target - Swaps.
56.009 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
56.009 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
56.009 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
56.009 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
56.029 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
56.029 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
56.050          Mounting dev-hugepages.mount - Huge Pages File System...
56.050          Mounting dev-mqueue.mount - POSIX Message Queue File System...
56.071          Mounting sys-kernel-debug.mount - Kernel Debug File System...
56.091          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
56.112          Starting systemd-journald.service - Journal Service...
56.133          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
56.174          Starting modprobe@configfs.service - Load Kernel Module configfs...
56.195          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
56.215          Starting modprobe@drm.service - Load Kernel Module drm...
56.236          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
56.236          Starting modprobe@fuse.service - Load Kernel Module fuse...
56.277          Starting modprobe@loop.service - Load Kernel Module loop...
56.318          Starting systemd-modules-load.service - Load Kernel Modules...
56.318          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
56.339          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
56.339 [  OK  ] Started systemd-journald.service - Journal Service.
56.360 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
56.360 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
56.360 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
56.380 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
56.401 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
56.422 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
56.442 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
56.463 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
56.463 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
56.463 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
56.484 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
56.484 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
56.505 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
56.546          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
56.587          Mounting sys-kernel-config.mount - Kernel Configuration File System...
56.608          Starting systemd-random-seed.service - Load/Save OS Random Seed...
56.629          Starting systemd-sysctl.service - Apply Kernel Variables...
56.629          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
56.649 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
56.649 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
56.691 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
56.732 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
56.753 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
56.836 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
56.858          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
56.879 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
56.879 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
56.900          Mounting tmp.mount - /tmp...
56.920          Mounting var-cache.mount - /var/cache...
56.941          Mounting var-log.mount - /var/log...
56.963          Mounting var-tmp.mount - /var/tmp...
56.984          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
56.984 [  OK  ] Mounted tmp.mount - /tmp.
57.005 [  OK  ] Mounted var-cache.mount - /var/cache.
57.005 [  OK  ] Mounted var-log.mount - /var/log.
57.005 [  OK  ] Mounted var-tmp.mount - /var/tmp.
57.026 [  OK  ] Reached target local-fs.target - Local File Systems.
57.047 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
57.047 [  OK  ] Reached target sockets.target - Socket Units.
57.067          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
57.131 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
57.152          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
57.216 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
57.238          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
57.281 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
57.387 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
57.414 [  OK  ] Reached target sysinit.target - System Initialization.
57.414 [  OK  ] Started apt-daily.timer - Daily apt download activities.
57.414 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
57.414 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
57.435 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
57.435 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
57.435 [  OK  ] Started motd-news.timer - Message of the Day.
57.435 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
57.457 [  OK  ] Reached target timers.target - Timer Units.
57.457 [  OK  ] Reached target basic.target - Basic System.
57.478          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
57.521          Starting getty-static.service - geâ¦bus and logind are not available...
57.542          Starting systemd-user-sessions.service - Permit User Sessions...
57.604          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
57.646 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
57.708 [  OK  ] Started getty@tty1.service - Getty on tty1.
57.814 [  OK  ] Started getty@tty2.service - Getty on tty2.
57.835 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
57.835 WRBOOT-EDD int13_dev81 mbr_signature=-
57.877 [  OK  ] Started getty@tty3.service - Getty on tty3.
57.920 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
57.983 WRBOOT-NET eth0 mac=52:54:00:77:11:49 
58.003 [  OK  ] Started getty@tty4.service - Getty on tty4.
58.003 WRBOOT-NET eth1 mac=52:54:00:77:12:c9 10.77.0.73/24 fe80::5054:ff:fe77:12c9/64 
58.025 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b2 kernel=6.8.0-151-generic
58.046 [  OK  ] Started getty@tty5.service - Getty on tty5.
58.088 [  OK  ] Started getty@tty6.service - Getty on tty6.
58.129 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
58.150 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
58.192 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
58.192 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
58.276 [  OK  ] Reached target getty.target - Login Prompts.
58.297 [  OK  ] Reached target multi-user.target - Multi-User System.
58.297 [  OK  ] Reached target graphical.target - Graphical Interface.
58.318          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
58.360 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
