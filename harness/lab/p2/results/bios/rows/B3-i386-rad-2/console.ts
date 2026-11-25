# tailts start epoch=1795464869.041
0.021 iPXE initialising devices...
0.246 
0.246 
0.246 
0.246 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.267 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.267 WRRUN-STUB
3.376 Configuring (net0 52:54:00:77:11:4a)...... ok
3.396 tftp://10.0.2.2/autoexec.ipxe... ok
3.396 WRRUN-BEGIN row=B3
3.438 Waiting for link-up on net1... ok
3.438 WRRUN-NET-OK
3.438 WRRUN-SAN-START sanboot
3.724 Registered SAN device 0x80
3.724 Booting from SAN device 0x80
5.608 GNU GRUB  version 2.14
5.608 
5.629 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
5.629       Press enter to boot the selected OS, `e' to edit the commands       
13.638       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
13.659 Starting systemd-udevd version 255.4-1ubuntu8.19
14.188 Begin: Loading essential drivers ... done.
14.188 Begin: Running /scripts/init-premount ... done.
14.229 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
14.229 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
14.535 RBFT-HOOK table found by source scan
14.535 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
14.535 RBFT-HOOK nic: eth1 address 10.77.0.74/24
14.535 RBFT-HOOK table check (source scan):
14.800 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
14.800 RBFT PASS signature: rBFT
14.800 RBFT PASS length: 234 bytes
14.800 RBFT PASS acpi_revision: 1
14.800 RBFT PASS checksum: all 234 bytes sum to 0
14.800 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
14.800 RBFT PASS magic: WRBT
14.800 RBFT PASS version: 1
14.800 RBFT PASS header_len: 116
14.800 RBFT PASS reserved: all reserved bytes are zero
14.800 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
14.800 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
14.800 RBFT PASS namespace: absent (as in version 1)
14.800 RBFT PASS rules: every rule of the field table holds
14.800 RBFT PASS entity: wrtest-p2-b3
14.800 RBFT PASS pool: winrbd
14.821 RBFT PASS image: wrtest-p2-b3
14.821 RBFT PASS image_id: 39648e0b332d
14.821 RBFT PASS snapshot: absent, as expected
14.821 RBFT PASS auth: cephx
14.821 RBFT PASS msgr_mode: crc
14.821 RBFT PASS flags: key,static (0x6)
14.821 RBFT PASS flag_readonly: clear
14.821 RBFT PASS flag_key: set
14.821 RBFT PASS flag_nic_static: set
14.821 RBFT PASS flag_vlan: clear
14.821 RBFT PASS flag_fsid: clear
14.821 RBFT PASS flag_secure_required: clear
14.821 RBFT PASS key_type: aes
14.821 RBFT PASS key_len: 16
14.821 RBFT INFO key: present in the table (aes, 16 bytes), not printed
14.821 RBFT PASS mon_count: 1
14.821 RBFT PASS mon0: 10.77.0.10:3300
14.821 RBFT PASS fsid: none, as expected
14.821 RBFT PASS nic_mac: 52:54:00:77:12:ca
14.821 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
14.821 RBFT PASS nic_vlan: 0
14.821 RBFT PASS nic_mtu: 1500
14.821 RBFT PASS nic_family: 4
14.821 RBFT PASS nic_ip: 10.77.0.74
14.821 RBFT PASS nic_prefix: 24
14.841 RBFT PASS nic_gateway: zero, as expected
14.841 RBFT PASS nic_dns: zero, as expected
14.841 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
14.841 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
14.841 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
14.841 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
14.841 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
14.841 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
14.841 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
14.841 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
14.841 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
14.841 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
14.841 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
14.862 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
14.862 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
14.862 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
14.862 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
14.862 RBFT-RESULT PASS pass=40 fail=0 skip=0
14.862 WRBOOT-TABLE PASS
14.903 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
14.964 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
14.964 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
14.964 done.
14.964 Begin: Running /scripts/local-premount ... done.
45.118 Warning: fsck not present, so skipping root file system
45.159 done.
45.200 Begin: Running /scripts/local-bottom ... done.
45.221 Begin: Running /scripts/init-bottom ... done.
47.042 
47.042 Welcome to Ubuntu 24.04 LTS!
47.042 
47.982 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
48.003 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
48.003 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
48.003 [  OK  ] Created slice user.slice - User and Session Slice.
48.003 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
48.023 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
48.023 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
48.023          Expecting device dev-ttyS0.device - /dev/ttyS0...
48.023 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
48.023 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
48.044 [  OK  ] Reached target paths.target - Path Units.
48.044 [  OK  ] Reached target remote-fs.target - Remote File Systems.
48.044 [  OK  ] Reached target slices.target - Slice Units.
48.044 [  OK  ] Reached target swap.target - Swaps.
48.044 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
48.065 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
48.065 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
48.065 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
48.065 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
48.085 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
48.106          Mounting dev-hugepages.mount - Huge Pages File System...
48.126          Mounting dev-mqueue.mount - POSIX Message Queue File System...
48.147          Mounting sys-kernel-debug.mount - Kernel Debug File System...
48.167          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
48.167          Starting systemd-journald.service - Journal Service...
48.188          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
48.209          Starting modprobe@configfs.service - Load Kernel Module configfs...
48.209          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
48.229          Starting modprobe@drm.service - Load Kernel Module drm...
48.250          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
48.250          Starting modprobe@fuse.service - Load Kernel Module fuse...
48.271          Starting modprobe@loop.service - Load Kernel Module loop...
48.291          Starting systemd-modules-load.service - Load Kernel Modules...
48.291          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
48.312          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
48.332 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
48.332 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
48.332 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
48.332 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
48.353 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
48.353 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
48.353 [  OK  ] Started systemd-journald.service - Journal Service.
48.373 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
48.373 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
48.394 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
48.394 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
48.394 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
48.394 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
48.435          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
48.435          Mounting sys-kernel-config.mount - Kernel Configuration File System...
48.456          Starting systemd-sysctl.service - Apply Kernel Variables...
48.456          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
48.539 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
48.559 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
48.580 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
48.621          Starting systemd-random-seed.service - Load/Save OS Random Seed...
48.641 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
48.683 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
48.724 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
48.724          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
48.765 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
48.765 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
48.785          Mounting tmp.mount - /tmp...
48.806          Mounting var-cache.mount - /var/cache...
48.826          Mounting var-log.mount - /var/log...
48.826          Mounting var-tmp.mount - /var/tmp...
48.847          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
48.847 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
48.847 [  OK  ] Mounted tmp.mount - /tmp.
48.868 [  OK  ] Mounted var-cache.mount - /var/cache.
48.868 [  OK  ] Mounted var-log.mount - /var/log.
48.868 [  OK  ] Mounted var-tmp.mount - /var/tmp.
48.888 [  OK  ] Reached target local-fs.target - Local File Systems.
48.888 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
48.888 [  OK  ] Reached target sockets.target - Socket Units.
48.909          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
48.950 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
48.970          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
49.031 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
49.052          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
49.093 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
49.176 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
49.176 [  OK  ] Reached target sysinit.target - System Initialization.
49.176 [  OK  ] Started apt-daily.timer - Daily apt download activities.
49.176 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
49.196 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
49.196 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
49.196 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
49.217 [  OK  ] Started motd-news.timer - Message of the Day.
49.217 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
49.217 [  OK  ] Reached target timers.target - Timer Units.
49.217 [  OK  ] Reached target basic.target - Basic System.
49.237          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
49.258          Starting getty-static.service - geâ¦bus and logind are not available...
49.279          Starting systemd-user-sessions.service - Permit User Sessions...
49.321          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
49.362 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
49.403 [  OK  ] Started getty@tty1.service - Getty on tty1.
49.465 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
49.465 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
49.609 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
49.793 [  OK  ] Started getty@tty2.service - Getty on tty2.
49.793 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
49.835 [  OK  ] Started getty@tty3.service - Getty on tty3.
49.835 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
49.835 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
49.855 [  OK  ] Started getty@tty4.service - Getty on tty4.
49.876 [  OK  ] Started getty@tty5.service - Getty on tty5.
49.876 [  OK  ] Started getty@tty6.service - Getty on tty6.
49.897 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
49.897 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
49.897 [  OK  ] Reached target getty.target - Login Prompts.
50.060 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
50.081 [  OK  ] Reached target multi-user.target - Multi-User System.
50.081 [  OK  ] Reached target graphical.target - Graphical Interface.
50.122          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
50.143 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
