# tailts start epoch=1795464923.889
7.927 iPXE initialising devices...
7.948 
7.968 
7.989 
8.009 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.050 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.050 WRRUN-STUB
11.198 Configuring (net0 52:54:00:77:12:c7)...... ok
11.239 tftp://10.77.0.10/autoexec.ipxe... ok
11.260 WRRUN-BEGIN row=B1
11.321 Waiting for link-up on net0... ok
11.342 WRRUN-NET-OK
11.363 WRRUN-SAN-START sanboot
11.813 Registered SAN device 0x80
11.834 Booting from SAN device 0x80
13.227 GNU GRUB  version 2.14
13.227 
13.247 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.268       Press enter to boot the selected OS, `e' to edit the commands       
49.022       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
49.085 Starting systemd-udevd version 255.4-1ubuntu8.19
49.778 Begin: Loading essential drivers ... done.
49.778 Begin: Running /scripts/init-premount ... done.
49.798 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
49.798 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
50.043 RBFT-HOOK table found by source scan
50.043 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
50.063 RBFT-HOOK nic: eth0 address 10.77.0.71/24
50.063 RBFT-HOOK table check (source scan):
50.308 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
50.308 RBFT PASS signature: rBFT
50.308 RBFT PASS length: 234 bytes
50.308 RBFT PASS acpi_revision: 1
50.308 RBFT PASS checksum: all 234 bytes sum to 0
50.308 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
50.308 RBFT PASS magic: WRBT
50.308 RBFT PASS version: 1
50.328 RBFT PASS header_len: 116
50.328 RBFT PASS reserved: all reserved bytes are zero
50.328 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
50.328 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
50.328 RBFT PASS namespace: absent (as in version 1)
50.328 RBFT PASS rules: every rule of the field table holds
50.328 RBFT PASS entity: wrtest-p2-b1
50.328 RBFT PASS pool: winrbd
50.328 RBFT PASS image: wrtest-p2-b1
50.328 RBFT PASS image_id: 38d9a2e0bcec
50.328 RBFT PASS snapshot: absent, as expected
50.328 RBFT PASS auth: cephx
50.328 RBFT PASS msgr_mode: crc
50.328 RBFT PASS flags: key,static (0x6)
50.328 RBFT PASS flag_readonly: clear
50.328 RBFT PASS flag_key: set
50.328 RBFT PASS flag_nic_static: set
50.349 RBFT PASS flag_vlan: clear
50.349 RBFT PASS flag_fsid: clear
50.349 RBFT PASS flag_secure_required: clear
50.349 RBFT PASS key_type: aes
50.349 RBFT PASS key_len: 16
50.349 RBFT INFO key: present in the table (aes, 16 bytes), not printed
50.349 RBFT PASS mon_count: 1
50.349 RBFT PASS mon0: 10.77.0.10:3300
50.349 RBFT PASS fsid: none, as expected
50.349 RBFT PASS nic_mac: 52:54:00:77:12:c7
50.349 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
50.349 RBFT PASS nic_vlan: 0
50.349 RBFT PASS nic_mtu: 1500
50.349 RBFT PASS nic_family: 4
50.349 RBFT PASS nic_ip: 10.77.0.71
50.349 RBFT PASS nic_prefix: 24
50.349 RBFT PASS nic_gateway: zero, as expected
50.349 RBFT PASS nic_dns: zero, as expected
50.370 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
50.370 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
50.370 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
50.370 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
50.370 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
50.370 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
50.370 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
50.370 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
50.370 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
50.370 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
50.390 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
50.390 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
50.390 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
50.390 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
50.390 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
50.390 RBFT-RESULT PASS pass=40 fail=0 skip=0
50.390 WRBOOT-TABLE PASS
50.431 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
50.513 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
50.513 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
50.513 done.
50.513 Begin: Running /scripts/local-premount ... done.
80.617 Warning: fsck not present, so skipping root file system
80.802 done.
80.844 Begin: Running /scripts/local-bottom ... done.
80.844 Begin: Running /scripts/init-bottom ... done.
82.583 
82.583 Welcome to Ubuntu 24.04 LTS!
82.583 
83.482 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
83.482 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
83.482 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
83.482 [  OK  ] Created slice user.slice - User and Session Slice.
83.503 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
83.503 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
83.503 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
83.503          Expecting device dev-ttyS0.device - /dev/ttyS0...
83.503 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
83.503 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
83.524 [  OK  ] Reached target paths.target - Path Units.
83.524 [  OK  ] Reached target remote-fs.target - Remote File Systems.
83.524 [  OK  ] Reached target slices.target - Slice Units.
83.524 [  OK  ] Reached target swap.target - Swaps.
83.524 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
83.524 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
83.524 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
83.544 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
83.544 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
83.544 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
83.565          Mounting dev-hugepages.mount - Huge Pages File System...
83.565          Mounting dev-mqueue.mount - POSIX Message Queue File System...
83.565          Mounting sys-kernel-debug.mount - Kernel Debug File System...
83.585          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
83.585          Starting systemd-journald.service - Journal Service...
83.606          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
83.627          Starting modprobe@configfs.service - Load Kernel Module configfs...
83.667          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
83.688          Starting modprobe@drm.service - Load Kernel Module drm...
83.709          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
83.729          Starting modprobe@fuse.service - Load Kernel Module fuse...
83.750          Starting modprobe@loop.service - Load Kernel Module loop...
83.770          Starting systemd-modules-load.service - Load Kernel Modules...
83.770          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
83.791          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
83.791 [  OK  ] Started systemd-journald.service - Journal Service.
83.811 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
83.811 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
83.811 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
83.811 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
83.811 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
83.832 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
83.832 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
83.832 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
83.852 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
83.852 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
83.852 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
83.873 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
83.893          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
83.914          Mounting sys-kernel-config.mount - Kernel Configuration File System...
83.934          Starting systemd-sysctl.service - Apply Kernel Variables...
83.955          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
83.955 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
83.955 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
83.975 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
83.996          Starting systemd-random-seed.service - Load/Save OS Random Seed...
84.037 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
84.037 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
84.078 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
84.098          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
84.119 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
84.119 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
84.139          Mounting tmp.mount - /tmp...
84.160          Mounting var-cache.mount - /var/cache...
84.160          Mounting var-log.mount - /var/log...
84.180          Mounting var-tmp.mount - /var/tmp...
84.180          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
84.201 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
84.201 [  OK  ] Mounted tmp.mount - /tmp.
84.201 [  OK  ] Mounted var-cache.mount - /var/cache.
84.201 [  OK  ] Mounted var-log.mount - /var/log.
84.201 [  OK  ] Mounted var-tmp.mount - /var/tmp.
84.221 [  OK  ] Reached target local-fs.target - Local File Systems.
84.221 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
84.221 [  OK  ] Reached target sockets.target - Socket Units.
84.242          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
84.262 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
84.262          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
84.324 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
84.344          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
84.365 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
84.385 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
84.406 [  OK  ] Reached target sysinit.target - System Initialization.
84.406 [  OK  ] Started apt-daily.timer - Daily apt download activities.
84.406 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
84.406 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
84.426 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
84.426 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
84.426 [  OK  ] Started motd-news.timer - Message of the Day.
84.447 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
84.447 [  OK  ] Reached target timers.target - Timer Units.
84.447 [  OK  ] Reached target basic.target - Basic System.
84.467          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
84.488          Starting getty-static.service - geâ¦bus and logind are not available...
84.508          Starting systemd-user-sessions.service - Permit User Sessions...
84.549          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
84.570 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
84.590 [  OK  ] Started getty@tty1.service - Getty on tty1.
84.652 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
84.672 [  OK  ] Started getty@tty2.service - Getty on tty2.
84.713 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
84.775 [  OK  ] Started getty@tty3.service - Getty on tty3.
84.795 [  OK  ] Started getty@tty4.service - Getty on tty4.
84.816 [  OK  ] Started getty@tty5.service - Getty on tty5.
84.816 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
84.816 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
84.836 [  OK  ] Started getty@tty6.service - Getty on tty6.
84.857 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
84.877 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
84.877 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
84.898 [  OK  ] Reached target getty.target - Login Prompts.
84.919 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
84.940 [  OK  ] Reached target multi-user.target - Multi-User System.
84.940 [  OK  ] Reached target graphical.target - Graphical Interface.
84.960          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
84.981 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
