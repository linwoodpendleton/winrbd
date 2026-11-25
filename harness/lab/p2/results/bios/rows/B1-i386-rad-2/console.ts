# tailts start epoch=1795465134.274
8.093 iPXE initialising devices...
8.134 
8.155 
8.175 
8.196 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.216 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.237 WRRUN-STUB
11.364 Configuring (net0 52:54:00:77:12:c7)...... ok
11.410 tftp://10.77.0.10/autoexec.ipxe... ok
11.541 WRRUN-BEGIN row=B1
11.583 Waiting for link-up on net0... ok
11.603 WRRUN-NET-OK
11.624 WRRUN-SAN-START sanboot
11.972 Registered SAN device 0x80
11.992 Booting from SAN device 0x80
14.863 GNU GRUB  version 2.14
14.863 
14.884 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.884       Press enter to boot the selected OS, `e' to edit the commands       
27.804       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
27.845 Starting systemd-udevd version 255.4-1ubuntu8.19
28.545 Begin: Loading essential drivers ... done.
28.545 Begin: Running /scripts/init-premount ... done.
28.586 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
28.586 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
28.872 RBFT-HOOK table found by source scan
28.872 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
28.872 RBFT-HOOK nic: eth0 address 10.77.0.71/24
28.872 RBFT-HOOK table check (source scan):
29.220 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
29.220 RBFT PASS signature: rBFT
29.220 RBFT PASS length: 234 bytes
29.220 RBFT PASS acpi_revision: 1
29.220 RBFT PASS checksum: all 234 bytes sum to 0
29.220 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
29.220 RBFT PASS magic: WRBT
29.220 RBFT PASS version: 1
29.220 RBFT PASS header_len: 116
29.241 RBFT PASS reserved: all reserved bytes are zero
29.241 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
29.241 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
29.241 RBFT PASS namespace: absent (as in version 1)
29.241 RBFT PASS rules: every rule of the field table holds
29.241 RBFT PASS entity: wrtest-p2-b1
29.241 RBFT PASS pool: winrbd
29.241 RBFT PASS image: wrtest-p2-b1
29.241 RBFT PASS image_id: 38d9a2e0bcec
29.241 RBFT PASS snapshot: absent, as expected
29.241 RBFT PASS auth: cephx
29.241 RBFT PASS msgr_mode: crc
29.241 RBFT PASS flags: key,static (0x6)
29.262 RBFT PASS flag_readonly: clear
29.262 RBFT PASS flag_key: set
29.262 RBFT PASS flag_nic_static: set
29.262 RBFT PASS flag_vlan: clear
29.262 RBFT PASS flag_fsid: clear
29.262 RBFT PASS flag_secure_required: clear
29.262 RBFT PASS key_type: aes
29.262 RBFT PASS key_len: 16
29.262 RBFT INFO key: present in the table (aes, 16 bytes), not printed
29.262 RBFT PASS mon_count: 1
29.262 RBFT PASS mon0: 10.77.0.10:3300
29.262 RBFT PASS fsid: none, as expected
29.262 RBFT PASS nic_mac: 52:54:00:77:12:c7
29.262 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
29.262 RBFT PASS nic_vlan: 0
29.262 RBFT PASS nic_mtu: 1500
29.262 RBFT PASS nic_family: 4
29.262 RBFT PASS nic_ip: 10.77.0.71
29.282 RBFT PASS nic_prefix: 24
29.282 RBFT PASS nic_gateway: zero, as expected
29.282 RBFT PASS nic_dns: zero, as expected
29.282 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
29.282 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
29.282 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
29.282 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
29.282 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
29.282 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
29.282 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.282 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.282 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
29.303 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
29.303 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
29.303 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
29.303 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
29.303 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
29.303 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
29.303 RBFT-RESULT PASS pass=40 fail=0 skip=0
29.303 WRBOOT-TABLE PASS
29.429 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
29.573 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
29.573 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
29.573 done.
29.573 Begin: Running /scripts/local-premount ... done.
59.706 Warning: fsck not present, so skipping root file system
59.726 done.
59.747 Begin: Running /scripts/local-bottom ... done.
59.768 Begin: Running /scripts/init-bottom ... done.
61.785 
61.785 Welcome to Ubuntu 24.04 LTS!
61.785 
62.850 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
62.871 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
62.871 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
62.871 [  OK  ] Created slice user.slice - User and Session Slice.
62.871 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
62.871 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
62.891 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
62.891          Expecting device dev-ttyS0.device - /dev/ttyS0...
62.891 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
62.891 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
62.891 [  OK  ] Reached target paths.target - Path Units.
62.891 [  OK  ] Reached target remote-fs.target - Remote File Systems.
62.912 [  OK  ] Reached target slices.target - Slice Units.
62.912 [  OK  ] Reached target swap.target - Swaps.
62.912 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
62.912 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
62.912 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
62.912 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
62.933 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
62.933 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
62.954          Mounting dev-hugepages.mount - Huge Pages File System...
62.954          Mounting dev-mqueue.mount - POSIX Message Queue File System...
62.974          Mounting sys-kernel-debug.mount - Kernel Debug File System...
62.995          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
62.995          Starting systemd-journald.service - Journal Service...
63.015          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
63.036          Starting modprobe@configfs.service - Load Kernel Module configfs...
63.036          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
63.057          Starting modprobe@drm.service - Load Kernel Module drm...
63.077          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
63.119          Starting modprobe@fuse.service - Load Kernel Module fuse...
63.139          Starting modprobe@loop.service - Load Kernel Module loop...
63.160          Starting systemd-modules-load.service - Load Kernel Modules...
63.160          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
63.180          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
63.180 [  OK  ] Started systemd-journald.service - Journal Service.
63.201 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
63.201 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
63.201 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
63.201 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
63.222 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
63.222 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
63.243 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
63.243 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
63.243 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
63.243 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
63.263 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
63.263 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
63.284          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
63.305          Mounting sys-kernel-config.mount - Kernel Configuration File System...
63.408          Starting systemd-sysctl.service - Apply Kernel Variables...
63.408          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
63.429 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
63.429 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
63.491 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
63.533          Starting systemd-random-seed.service - Load/Save OS Random Seed...
63.574 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
63.574 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
63.615 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
63.636          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
63.657 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
63.678 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
63.698          Mounting tmp.mount - /tmp...
63.719          Mounting var-cache.mount - /var/cache...
63.740          Mounting var-log.mount - /var/log...
63.761          Mounting var-tmp.mount - /var/tmp...
63.782          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
63.782 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
63.782 [  OK  ] Mounted tmp.mount - /tmp.
63.782 [  OK  ] Mounted var-cache.mount - /var/cache.
63.782 [  OK  ] Mounted var-log.mount - /var/log.
63.803 [  OK  ] Mounted var-tmp.mount - /var/tmp.
63.803 [  OK  ] Reached target local-fs.target - Local File Systems.
63.824 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
63.824 [  OK  ] Reached target sockets.target - Socket Units.
63.844          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
63.865 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
63.885          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
63.947 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
63.968          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
63.989 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
64.051 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
64.051 [  OK  ] Reached target sysinit.target - System Initialization.
64.051 [  OK  ] Started apt-daily.timer - Daily apt download activities.
64.051 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
64.051 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
64.072 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
64.072 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
64.072 [  OK  ] Started motd-news.timer - Message of the Day.
64.072 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
64.072 [  OK  ] Reached target timers.target - Timer Units.
64.092 [  OK  ] Reached target basic.target - Basic System.
64.092          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
64.113          Starting getty-static.service - geâ¦bus and logind are not available...
64.134          Starting systemd-user-sessions.service - Permit User Sessions...
64.175          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
64.217 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
64.258 [  OK  ] Started getty@tty1.service - Getty on tty1.
64.299 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
64.403 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
64.423 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
64.505 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
64.525 [  OK  ] Started getty@tty2.service - Getty on tty2.
64.546 [  OK  ] Started getty@tty3.service - Getty on tty3.
64.566 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
64.587 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
64.608 [  OK  ] Started getty@tty4.service - Getty on tty4.
64.628 [  OK  ] Started getty@tty5.service - Getty on tty5.
64.649 [  OK  ] Started getty@tty6.service - Getty on tty6.
64.670 [  OK  ] Reached target getty.target - Login Prompts.
64.670 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
64.752 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
64.752 [  OK  ] Reached target multi-user.target - Multi-User System.
64.772 [  OK  ] Reached target graphical.target - Graphical Interface.
64.793          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
64.834 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
