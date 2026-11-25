# tailts start epoch=1795464778.021
0.267 iPXE initialising devices...
0.761 
0.761 
0.761 
0.761 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.782 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.782 WRRUN-STUB
4.027 Configuring (net0 52:54:00:77:11:4a)...... ok
4.276 tftp://10.0.2.2/autoexec.ipxe... ok
4.276 WRRUN-BEGIN row=B3
4.338 Waiting for link-up on net1... ok
4.338 WRRUN-NET-OK
4.338 WRRUN-SAN-START sanboot
4.768 Registered SAN device 0x80
4.768 Booting from SAN device 0x80
6.078 GNU GRUB  version 2.14
6.078 
6.099 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
6.099       Press enter to boot the selected OS, `e' to edit the commands       
44.247       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
44.288 Starting systemd-udevd version 255.4-1ubuntu8.19
45.132 Begin: Loading essential drivers ... done.
45.153 Begin: Running /scripts/init-premount ... done.
45.173 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
45.173 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
45.459 RBFT-HOOK table found by source scan
45.459 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
45.459 RBFT-HOOK nic: eth1 address 10.77.0.74/24
45.459 RBFT-HOOK table check (source scan):
46.055 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
46.055 RBFT PASS signature: rBFT
46.055 RBFT PASS length: 234 bytes
46.055 RBFT PASS acpi_revision: 1
46.055 RBFT PASS checksum: all 234 bytes sum to 0
46.055 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
46.055 RBFT PASS magic: WRBT
46.076 RBFT PASS version: 1
46.076 RBFT PASS header_len: 116
46.076 RBFT PASS reserved: all reserved bytes are zero
46.076 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
46.076 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
46.076 RBFT PASS namespace: absent (as in version 1)
46.076 RBFT PASS rules: every rule of the field table holds
46.076 RBFT PASS entity: wrtest-p2-b3
46.076 RBFT PASS pool: winrbd
46.076 RBFT PASS image: wrtest-p2-b3
46.097 RBFT PASS image_id: 39648e0b332d
46.097 RBFT PASS snapshot: absent, as expected
46.097 RBFT PASS auth: cephx
46.097 RBFT PASS msgr_mode: crc
46.097 RBFT PASS flags: key,static (0x6)
46.097 RBFT PASS flag_readonly: clear
46.097 RBFT PASS flag_key: set
46.097 RBFT PASS flag_nic_static: set
46.097 RBFT PASS flag_vlan: clear
46.097 RBFT PASS flag_fsid: clear
46.097 RBFT PASS flag_secure_required: clear
46.097 RBFT PASS key_type: aes
46.097 RBFT PASS key_len: 16
46.097 RBFT INFO key: present in the table (aes, 16 bytes), not printed
46.097 RBFT PASS mon_count: 1
46.097 RBFT PASS mon0: 10.77.0.10:3300
46.117 RBFT PASS fsid: none, as expected
46.117 RBFT PASS nic_mac: 52:54:00:77:12:ca
46.117 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
46.117 RBFT PASS nic_vlan: 0
46.117 RBFT PASS nic_mtu: 1500
46.117 RBFT PASS nic_family: 4
46.117 RBFT PASS nic_ip: 10.77.0.74
46.117 RBFT PASS nic_prefix: 24
46.117 RBFT PASS nic_gateway: zero, as expected
46.117 RBFT PASS nic_dns: zero, as expected
46.117 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
46.138 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
46.138 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
46.138 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
46.138 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
46.138 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
46.138 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
46.138 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
46.138 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
46.158 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
46.158 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
46.158 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
46.158 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
46.158 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
46.158 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
46.158 RBFT-RESULT PASS pass=40 fail=0 skip=0
46.158 WRBOOT-TABLE PASS
46.220 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
46.281 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
46.281 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
46.281 done.
46.301 Begin: Running /scripts/local-premount ... done.
76.393 Warning: fsck not present, so skipping root file system
76.414 done.
76.455 Begin: Running /scripts/local-bottom ... done.
76.475 Begin: Running /scripts/init-bottom ... done.
77.956 
77.956 Welcome to Ubuntu 24.04 LTS!
77.956 
79.214 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
79.214 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
79.214 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
79.214 [  OK  ] Created slice user.slice - User and Session Slice.
79.214 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
79.235 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
79.235 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
79.235          Expecting device dev-ttyS0.device - /dev/ttyS0...
79.235 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
79.235 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
79.235 [  OK  ] Reached target paths.target - Path Units.
79.235 [  OK  ] Reached target remote-fs.target - Remote File Systems.
79.256 [  OK  ] Reached target slices.target - Slice Units.
79.256 [  OK  ] Reached target swap.target - Swaps.
79.256 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
79.256 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
79.256 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
79.276 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
79.276 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
79.276 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
79.297          Mounting dev-hugepages.mount - Huge Pages File System...
79.297          Mounting dev-mqueue.mount - POSIX Message Queue File System...
79.318          Mounting sys-kernel-debug.mount - Kernel Debug File System...
79.318          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
79.339          Starting systemd-journald.service - Journal Service...
79.360          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
79.360          Starting modprobe@configfs.service - Load Kernel Module configfs...
79.380          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
79.380          Starting modprobe@drm.service - Load Kernel Module drm...
79.422          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
79.443          Starting modprobe@fuse.service - Load Kernel Module fuse...
79.464          Starting modprobe@loop.service - Load Kernel Module loop...
79.773          Starting systemd-modules-load.service - Load Kernel Modules...
79.836          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
79.836          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
79.857 [  OK  ] Started systemd-journald.service - Journal Service.
79.857 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
79.857 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
79.878 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
79.878 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
79.919 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
79.981 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
79.981 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
80.002 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
80.002 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
80.002 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
80.022 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
80.043 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
80.043 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
80.084          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
80.104          Mounting sys-kernel-config.mount - Kernel Configuration File System...
80.125          Starting systemd-random-seed.service - Load/Save OS Random Seed...
80.145          Starting systemd-sysctl.service - Apply Kernel Variables...
80.166          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
80.166 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
80.186 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
80.186 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
80.227 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
80.309 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
80.330 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
80.330          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
80.350 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
80.371 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
80.371          Mounting tmp.mount - /tmp...
80.392          Mounting var-cache.mount - /var/cache...
80.413          Mounting var-log.mount - /var/log...
80.413          Mounting var-tmp.mount - /var/tmp...
80.433          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
80.433 [  OK  ] Mounted tmp.mount - /tmp.
80.433 [  OK  ] Mounted var-cache.mount - /var/cache.
80.433 [  OK  ] Mounted var-log.mount - /var/log.
80.454 [  OK  ] Mounted var-tmp.mount - /var/tmp.
80.454 [  OK  ] Reached target local-fs.target - Local File Systems.
80.454 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
80.454 [  OK  ] Reached target sockets.target - Socket Units.
80.830          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
80.933 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
80.954          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
81.016 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
81.036          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
81.078 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
81.241 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
81.241 [  OK  ] Reached target sysinit.target - System Initialization.
81.241 [  OK  ] Started apt-daily.timer - Daily apt download activities.
81.241 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
81.241 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
81.262 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
81.262 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
81.262 [  OK  ] Started motd-news.timer - Message of the Day.
81.262 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
81.262 [  OK  ] Reached target timers.target - Timer Units.
81.262 [  OK  ] Reached target basic.target - Basic System.
81.283          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
81.304          Starting getty-static.service - geâ¦bus and logind are not available...
81.324          Starting systemd-user-sessions.service - Permit User Sessions...
81.345          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
81.366 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
81.407 [  OK  ] Started getty@tty1.service - Getty on tty1.
81.531 [  OK  ] Started getty@tty2.service - Getty on tty2.
81.634 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
81.716 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
81.736 [  OK  ] Started getty@tty3.service - Getty on tty3.
81.757 [  OK  ] Started getty@tty4.service - Getty on tty4.
81.818 [  OK  ] Started getty@tty5.service - Getty on tty5.
81.818 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
81.839 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
81.839 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
81.860 [  OK  ] Started getty@tty6.service - Getty on tty6.
81.860 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
81.881 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
81.881 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
81.984 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
81.984 [  OK  ] Reached target getty.target - Login Prompts.
82.004 [  OK  ] Reached target multi-user.target - Multi-User System.
82.004 [  OK  ] Reached target graphical.target - Graphical Interface.
82.025          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
