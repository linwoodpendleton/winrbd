# tailts start epoch=1795480539.457
0.000 iPXE initialising devices...
0.206 
0.206 
0.206 
0.227 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.227 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.247 WRRUN-STUB
3.352 Configuring (net0 52:54:00:77:11:4a)...... ok
3.373 tftp://10.0.2.2/autoexec.ipxe... ok
3.373 WRRUN-BEGIN row=B3
3.414 Waiting for link-up on net1... ok
3.414 WRRUN-NET-OK
3.414 WRRUN-SAN-START sanboot
3.435 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.435 rbd: core stack high-water 512 of 16384 bytes
3.456 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.456 rbd: core stack high-water 760 of 16384 bytes
3.498 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.498 rbd: core stack high-water 1304 of 16384 bytes
3.518 rbd: stack high-water 2096 of 4096 bytes (2000 left)
3.560 rbd: core stack high-water 1588 of 16384 bytes
3.767 Registered SAN device 0x80
3.788 Booting from SAN device 0x80
3.808 rbd: stack high-water 2676 of 4096 bytes (1420 left)
3.829 rbd: core stack high-water 1696 of 16384 bytes
5.128 GNU GRUB  version 2.14
5.128 
5.149 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.149       Press enter to boot the selected OS, `e' to edit the commands       
12.183       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
12.225 Starting systemd-udevd version 255.4-1ubuntu8.19
12.821 Begin: Loading essential drivers ... done.
12.821 Begin: Running /scripts/init-premount ... done.
12.842 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
12.842 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
13.110 RBFT-HOOK table found by source scan
13.130 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
13.130 RBFT-HOOK nic: eth1 address 10.77.0.74/24
13.130 RBFT-HOOK table check (source scan):
13.460 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
13.460 RBFT PASS signature: rBFT
13.460 RBFT PASS length: 234 bytes
13.460 RBFT PASS acpi_revision: 1
13.460 RBFT PASS checksum: all 234 bytes sum to 0
13.460 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
13.460 RBFT PASS magic: WRBT
13.460 RBFT PASS version: 1
13.460 RBFT PASS header_len: 116
13.460 RBFT PASS reserved: all reserved bytes are zero
13.481 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
13.481 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
13.481 RBFT PASS namespace: absent (as in version 1)
13.481 RBFT PASS rules: every rule of the field table holds
13.481 RBFT PASS entity: wrtest-p2-b3
13.481 RBFT PASS pool: winrbd
13.481 RBFT PASS image: wrtest-p2-b3
13.481 RBFT PASS image_id: 3fc6592539a3
13.481 RBFT PASS snapshot: absent, as expected
13.481 RBFT PASS auth: cephx
13.481 RBFT PASS msgr_mode: crc
13.481 RBFT PASS flags: key,static (0x6)
13.481 RBFT PASS flag_readonly: clear
13.481 RBFT PASS flag_key: set
13.481 RBFT PASS flag_nic_static: set
13.481 RBFT PASS flag_vlan: clear
13.481 RBFT PASS flag_fsid: clear
13.481 RBFT PASS flag_secure_required: clear
13.481 RBFT PASS key_type: aes
13.481 RBFT PASS key_len: 16
13.502 RBFT INFO key: present in the table (aes, 16 bytes), not printed
13.502 RBFT PASS mon_count: 1
13.502 RBFT PASS mon0: 10.77.0.10:3300
13.502 RBFT PASS fsid: none, as expected
13.502 RBFT PASS nic_mac: 52:54:00:77:12:ca
13.502 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
13.502 RBFT PASS nic_vlan: 0
13.502 RBFT PASS nic_mtu: 1500
13.502 RBFT PASS nic_family: 4
13.502 RBFT PASS nic_ip: 10.77.0.74
13.502 RBFT PASS nic_prefix: 24
13.502 RBFT PASS nic_gateway: zero, as expected
13.502 RBFT PASS nic_dns: zero, as expected
13.502 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 94 46 45 4e 53 59 53
13.502 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
13.502 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
13.502 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
13.523 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
13.523 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
13.523 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
13.523 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
13.523 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
13.523 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
13.523 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
13.523 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 66 63 36 35 39 32
13.523 RBFT DUMP 00c0: 35 33 39 61 33 00 04 00 e4 0c 0a 4d 00 0a 00 00
13.523 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
13.544 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
13.544 RBFT-RESULT PASS pass=40 fail=0 skip=0
13.544 WRBOOT-TABLE PASS
13.585 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
13.668 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
13.668 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
13.668 done.
13.668 Begin: Running /scripts/local-premount ... done.
43.827 Warning: fsck not present, so skipping root file system
43.848 done.
43.869 Begin: Running /scripts/local-bottom ... done.
43.890 Begin: Running /scripts/init-bottom ... done.
45.435 
45.435 Welcome to Ubuntu 24.04 LTS!
45.435 
46.546 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
46.546 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
46.546 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
46.566 [  OK  ] Created slice user.slice - User and Session Slice.
46.566 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
46.566 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
46.587 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
46.587          Expecting device dev-ttyS0.device - /dev/ttyS0...
46.587 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
46.587 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
46.587 [  OK  ] Reached target paths.target - Path Units.
46.587 [  OK  ] Reached target remote-fs.target - Remote File Systems.
46.608 [  OK  ] Reached target slices.target - Slice Units.
46.608 [  OK  ] Reached target swap.target - Swaps.
46.608 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
46.608 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
46.608 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
46.629 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
46.629 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
46.629 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
46.649          Mounting dev-hugepages.mount - Huge Pages File System...
46.670          Mounting dev-mqueue.mount - POSIX Message Queue File System...
46.691          Mounting sys-kernel-debug.mount - Kernel Debug File System...
46.691          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
46.732          Starting systemd-journald.service - Journal Service...
46.753          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
46.774          Starting modprobe@configfs.service - Load Kernel Module configfs...
46.816          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
46.837          Starting modprobe@drm.service - Load Kernel Module drm...
46.857          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
46.878          Starting modprobe@fuse.service - Load Kernel Module fuse...
46.878          Starting modprobe@loop.service - Load Kernel Module loop...
46.899          Starting systemd-modules-load.service - Load Kernel Modules...
46.920          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
46.940          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
46.961 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
46.961 [  OK  ] Started systemd-journald.service - Journal Service.
46.982 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
46.982 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
46.982 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
47.003 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
47.003 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
47.024 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
47.045 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
47.066 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
47.086 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
47.086 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
47.086 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
47.107 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
47.128          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
47.149          Mounting sys-kernel-config.mount - Kernel Configuration File System...
47.170          Starting systemd-random-seed.service - Load/Save OS Random Seed...
47.190          Starting systemd-sysctl.service - Apply Kernel Variables...
47.211          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
47.232 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
47.232 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
47.253 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
47.335 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
47.356 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
47.397          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
47.417 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
47.438 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
47.438 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
47.459          Mounting tmp.mount - /tmp...
47.501          Mounting var-cache.mount - /var/cache...
47.523          Mounting var-log.mount - /var/log...
47.543          Mounting var-tmp.mount - /var/tmp...
47.543          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
47.564 [  OK  ] Mounted tmp.mount - /tmp.
47.564 [  OK  ] Mounted var-cache.mount - /var/cache.
47.564 [  OK  ] Mounted var-log.mount - /var/log.
47.564 [  OK  ] Mounted var-tmp.mount - /var/tmp.
47.585 [  OK  ] Reached target local-fs.target - Local File Systems.
47.606 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
47.606 [  OK  ] Reached target sockets.target - Socket Units.
47.627          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
47.668 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
47.690          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
47.774 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
47.774          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
47.815 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
47.856 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
47.856 [  OK  ] Reached target sysinit.target - System Initialization.
47.856 [  OK  ] Started apt-daily.timer - Daily apt download activities.
47.856 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
47.877 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
47.877 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
47.877 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
47.877 [  OK  ] Started motd-news.timer - Message of the Day.
47.898 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
47.898 [  OK  ] Reached target timers.target - Timer Units.
47.898 [  OK  ] Reached target basic.target - Basic System.
47.919          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
47.939          Starting getty-static.service - geâ¦bus and logind are not available...
47.960          Starting systemd-user-sessions.service - Permit User Sessions...
47.981          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
48.044 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
48.106 [  OK  ] Started getty@tty1.service - Getty on tty1.
48.127 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
48.168 [  OK  ] Started getty@tty2.service - Getty on tty2.
48.209 [  OK  ] Started getty@tty3.service - Getty on tty3.
48.209 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
48.230 [  OK  ] Started getty@tty4.service - Getty on tty4.
48.251 [  OK  ] Started getty@tty5.service - Getty on tty5.
48.271 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
48.292 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
48.333 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
48.374 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
48.395 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
48.395 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
48.416 [  OK  ] Started getty@tty6.service - Getty on tty6.
48.416 [  OK  ] Reached target getty.target - Login Prompts.
48.437 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
48.437 [  OK  ] Reached target multi-user.target - Multi-User System.
48.437 [  OK  ] Reached target graphical.target - Graphical Interface.
48.458          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
48.500 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
