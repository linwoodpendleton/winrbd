# tailts start epoch=1795479839.727
7.784 iPXE initialising devices...
7.804 
7.825 
7.846 
7.867 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.888 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.909 WRRUN-STUB
11.387 Configuring (net0 52:54:00:77:12:c7)...... ok
11.407 tftp://10.77.0.10/autoexec.ipxe... ok
11.428 WRRUN-BEGIN row=B1
11.490 Waiting for link-up on net0... ok
11.510 WRRUN-NET-OK
11.531 WRRUN-SAN-START sanboot
11.572 rbd: stack high-water 2096 of 16384 bytes (14288 left)
11.654 rbd: stack high-water 2696 of 16384 bytes (13688 left)
11.675 rbd: stack high-water 2980 of 16384 bytes (13404 left)
11.777 rbd: stack high-water 3232 of 16384 bytes (13152 left)
11.798 Registered SAN device 0x80
11.819 Booting from SAN device 0x80
11.839 rbd: stack high-water 3380 of 16384 bytes (13004 left)
12.842 rbd: stack high-water 4048 of 16384 bytes (12336 left)
14.377 GNU GRUB  version 2.14
14.377 
14.397 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.397       Press enter to boot the selected OS, `e' to edit the commands       
55.477       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)
84.792 Loading, please wait...
84.833 Starting systemd-udevd version 255.4-1ubuntu8.19
85.450 Begin: Loading essential drivers ... done.
85.450 Begin: Running /scripts/init-premount ... done.
85.491 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
85.491 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
85.800 RBFT-HOOK table found by source scan
85.800 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
85.800 RBFT-HOOK nic: eth0 address 10.77.0.71/24
85.800 RBFT-HOOK table check (source scan):
86.088 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
86.088 RBFT PASS signature: rBFT
86.108 RBFT PASS length: 234 bytes
86.108 RBFT PASS acpi_revision: 1
86.108 RBFT PASS checksum: all 234 bytes sum to 0
86.108 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
86.108 RBFT PASS magic: WRBT
86.108 RBFT PASS version: 1
86.108 RBFT PASS header_len: 116
86.108 RBFT PASS reserved: all reserved bytes are zero
86.108 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
86.108 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
86.108 RBFT PASS namespace: absent (as in version 1)
86.108 RBFT PASS rules: every rule of the field table holds
86.108 RBFT PASS entity: wrtest-p2-b1
86.108 RBFT PASS pool: winrbd
86.108 RBFT PASS image: wrtest-p2-b1
86.108 RBFT PASS image_id: 3fae3418fe30
86.130 RBFT PASS snapshot: absent, as expected
86.130 RBFT PASS auth: cephx
86.130 RBFT PASS msgr_mode: crc
86.130 RBFT PASS flags: key,static (0x6)
86.130 RBFT PASS flag_readonly: clear
86.130 RBFT PASS flag_key: set
86.130 RBFT PASS flag_nic_static: set
86.130 RBFT PASS flag_vlan: clear
86.130 RBFT PASS flag_fsid: clear
86.130 RBFT PASS flag_secure_required: clear
86.130 RBFT PASS key_type: aes
86.130 RBFT PASS key_len: 16
86.130 RBFT INFO key: present in the table (aes, 16 bytes), not printed
86.130 RBFT PASS mon_count: 1
86.130 RBFT PASS mon0: 10.77.0.10:3300
86.130 RBFT PASS fsid: none, as expected
86.130 RBFT PASS nic_mac: 52:54:00:77:12:c7
86.130 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
86.130 RBFT PASS nic_vlan: 0
86.130 RBFT PASS nic_mtu: 1500
86.130 RBFT PASS nic_family: 4
86.130 RBFT PASS nic_ip: 10.77.0.71
86.130 RBFT PASS nic_prefix: 24
86.130 RBFT PASS nic_gateway: zero, as expected
86.130 RBFT PASS nic_dns: zero, as expected
86.151 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
86.151 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
86.151 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
86.151 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
86.151 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
86.151 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
86.151 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
86.151 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
86.151 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
86.151 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
86.151 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
86.172 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
86.172 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
86.172 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
86.172 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
86.172 RBFT-RESULT PASS pass=40 fail=0 skip=0
86.172 WRBOOT-TABLE PASS
86.235 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
86.297 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
86.297 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
86.297 done.
86.318 Begin: Running /scripts/local-premount ... done.
116.453 Warning: fsck not present, so skipping root file system
116.494 done.
116.494 Begin: Running /scripts/local-bottom ... done.
116.535 Begin: Running /scripts/init-bottom ... done.
117.661 
117.661 Welcome to Ubuntu 24.04 LTS!
117.661 
118.753 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
118.774 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
118.774 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
118.774 [  OK  ] Created slice user.slice - User and Session Slice.
118.794 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
118.794 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
118.794 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
118.794          Expecting device dev-ttyS0.device - /dev/ttyS0...
118.794 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
118.794 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
118.794 [  OK  ] Reached target paths.target - Path Units.
118.815 [  OK  ] Reached target remote-fs.target - Remote File Systems.
118.815 [  OK  ] Reached target slices.target - Slice Units.
118.815 [  OK  ] Reached target swap.target - Swaps.
118.815 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
118.815 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
118.815 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
118.836 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
118.836 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
118.836 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
118.857          Mounting dev-hugepages.mount - Huge Pages File System...
118.857          Mounting dev-mqueue.mount - POSIX Message Queue File System...
118.877          Mounting sys-kernel-debug.mount - Kernel Debug File System...
118.877          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
118.898          Starting systemd-journald.service - Journal Service...
118.898          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
118.919          Starting modprobe@configfs.service - Load Kernel Module configfs...
118.940          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
118.960          Starting modprobe@drm.service - Load Kernel Module drm...
118.960          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
118.981          Starting modprobe@fuse.service - Load Kernel Module fuse...
119.001          Starting modprobe@loop.service - Load Kernel Module loop...
119.022          Starting systemd-modules-load.service - Load Kernel Modules...
119.022          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
119.043          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
119.043 [  OK  ] Started systemd-journald.service - Journal Service.
119.043 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
119.064 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
119.064 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
119.064 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
119.064 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
119.084 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
119.084 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
119.084 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
119.105 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
119.105 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
119.105 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
119.105 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
119.147          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
119.147          Mounting sys-kernel-config.mount - Kernel Configuration File System...
119.167          Starting systemd-sysctl.service - Apply Kernel Variables...
119.188          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
119.209 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
119.209 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
119.229 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
119.271          Starting systemd-random-seed.service - Load/Save OS Random Seed...
119.313 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
119.313 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
119.375 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
119.396          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
119.417 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
119.417 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
119.437          Mounting tmp.mount - /tmp...
119.458          Mounting var-cache.mount - /var/cache...
119.479          Mounting var-log.mount - /var/log...
119.499          Mounting var-tmp.mount - /var/tmp...
119.499          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
119.520 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
119.520 [  OK  ] Mounted tmp.mount - /tmp.
119.520 [  OK  ] Mounted var-cache.mount - /var/cache.
119.520 [  OK  ] Mounted var-log.mount - /var/log.
119.520 [  OK  ] Mounted var-tmp.mount - /var/tmp.
119.541 [  OK  ] Reached target local-fs.target - Local File Systems.
119.541 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
119.541 [  OK  ] Reached target sockets.target - Socket Units.
119.561          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
119.603 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
119.603          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
119.664 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
119.664          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
119.705 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
119.828 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
119.828 [  OK  ] Reached target sysinit.target - System Initialization.
119.849 [  OK  ] Started apt-daily.timer - Daily apt download activities.
119.849 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
119.849 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
119.849 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
119.869 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
119.869 [  OK  ] Started motd-news.timer - Message of the Day.
119.869 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
119.869 [  OK  ] Reached target timers.target - Timer Units.
119.869 [  OK  ] Reached target basic.target - Basic System.
119.890          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
119.911          Starting getty-static.service - geâ¦bus and logind are not available...
119.932          Starting systemd-user-sessions.service - Permit User Sessions...
119.953          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
119.994 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
120.015 [  OK  ] Started getty@tty1.service - Getty on tty1.
120.077 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
120.118 [  OK  ] Started getty@tty2.service - Getty on tty2.
120.201 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
120.221 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
120.221 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
120.221 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
120.243 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
120.263 [  OK  ] Started getty@tty3.service - Getty on tty3.
120.284 [  OK  ] Started getty@tty4.service - Getty on tty4.
120.305 [  OK  ] Started getty@tty5.service - Getty on tty5.
120.326 [  OK  ] Started getty@tty6.service - Getty on tty6.
120.347 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
120.347 [  OK  ] Reached target getty.target - Login Prompts.
120.347 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
120.368 [  OK  ] Reached target multi-user.target - Multi-User System.
120.389 [  OK  ] Reached target graphical.target - Graphical Interface.
120.389          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
120.430 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
