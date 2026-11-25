# tailts start epoch=1795463390.388
7.941 iPXE initialising devices...
7.961 
7.982 
8.002 
8.023 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.064 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.084 WRRUN-STUB
11.219 Configuring (net0 52:54:00:77:12:c7)...... ok
11.260 tftp://10.77.0.10/autoexec.ipxe... ok
11.280 WRRUN-BEGIN row=B1
11.343 Waiting for link-up on net0... ok
11.364 WRRUN-NET-OK
11.426 WRRUN-SAN-START sanboot
11.508 rbd: stack monitor: the stack is not iPXE's own (frame 0x7fe8edd8, internal stack 0xffffffffeb463660 to 0xffffffffeb465660): not painted
11.815 Registered SAN device 0x80
11.835 Booting from SAN device 0x80
11.998 rbd: stack monitor: the stack is not iPXE's own (frame 0x7fe8ea58, internal stack 0xffffffffeb463660 to 0xffffffffeb465660): not painted
15.164 GNU GRUB  version 2.14
15.164 
15.185 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
15.185       Press enter to boot the selected OS, `e' to edit the commands       
37.595       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
37.636 Starting systemd-udevd version 255.4-1ubuntu8.19
38.248 Begin: Loading essential drivers ... done.
38.248 Begin: Running /scripts/init-premount ... done.
38.269 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
38.269 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
38.806 RBFT-HOOK table found by source scan
38.806 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
38.806 RBFT-HOOK nic: eth0 address 10.77.0.71/24
38.806 RBFT-HOOK table check (source scan):
39.072 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
39.072 RBFT PASS signature: rBFT
39.072 RBFT PASS length: 234 bytes
39.072 RBFT PASS acpi_revision: 1
39.072 RBFT PASS checksum: all 234 bytes sum to 0
39.072 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
39.072 RBFT PASS magic: WRBT
39.072 RBFT PASS version: 1
39.072 RBFT PASS header_len: 116
39.072 RBFT PASS reserved: all reserved bytes are zero
39.072 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
39.072 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
39.072 RBFT PASS namespace: absent (as in version 1)
39.072 RBFT PASS rules: every rule of the field table holds
39.072 RBFT PASS entity: wrtest-p2-b1
39.093 RBFT PASS pool: winrbd
39.093 RBFT PASS image: wrtest-p2-b1
39.093 RBFT PASS image_id: 38d9a2e0bcec
39.093 RBFT PASS snapshot: absent, as expected
39.093 RBFT PASS auth: cephx
39.093 RBFT PASS msgr_mode: crc
39.093 RBFT PASS flags: key,static (0x6)
39.093 RBFT PASS flag_readonly: clear
39.093 RBFT PASS flag_key: set
39.093 RBFT PASS flag_nic_static: set
39.093 RBFT PASS flag_vlan: clear
39.093 RBFT PASS flag_fsid: clear
39.093 RBFT PASS flag_secure_required: clear
39.093 RBFT PASS key_type: aes
39.093 RBFT PASS key_len: 16
39.093 RBFT INFO key: present in the table (aes, 16 bytes), not printed
39.093 RBFT PASS mon_count: 1
39.093 RBFT PASS mon0: 10.77.0.10:3300
39.093 RBFT PASS fsid: none, as expected
39.093 RBFT PASS nic_mac: 52:54:00:77:12:c7
39.093 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
39.093 RBFT PASS nic_vlan: 0
39.093 RBFT PASS nic_mtu: 1500
39.093 RBFT PASS nic_family: 4
39.093 RBFT PASS nic_ip: 10.77.0.71
39.114 RBFT PASS nic_prefix: 24
39.114 RBFT PASS nic_gateway: zero, as expected
39.114 RBFT PASS nic_dns: zero, as expected
39.114 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
39.114 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
39.114 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
39.114 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
39.114 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
39.114 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
39.114 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
39.114 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
39.114 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
39.114 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
39.135 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
39.135 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
39.135 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
39.135 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
39.135 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
39.135 RBFT-RESULT PASS pass=40 fail=0 skip=0
39.135 WRBOOT-TABLE PASS
39.197 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
39.258 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
39.258 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
39.258 done.
39.279 Begin: Running /scripts/local-premount ... done.
69.769 Warning: fsck not present, so skipping root file system
70.000 done.
70.043 Begin: Running /scripts/local-bottom ... done.
70.064 Begin: Running /scripts/init-bottom ... done.
71.845 
71.845 Welcome to Ubuntu 24.04 LTS!
71.845 
72.929 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
72.950 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
72.950 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
72.950 [  OK  ] Created slice user.slice - User and Session Slice.
72.950 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
72.950 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
72.950 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
72.950          Expecting device dev-ttyS0.device - /dev/ttyS0...
72.970 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
72.970 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
72.970 [  OK  ] Reached target paths.target - Path Units.
72.970 [  OK  ] Reached target remote-fs.target - Remote File Systems.
72.970 [  OK  ] Reached target slices.target - Slice Units.
72.970 [  OK  ] Reached target swap.target - Swaps.
72.970 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
72.970 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
72.991 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
72.991 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
72.991 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
72.991 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
73.012          Mounting dev-hugepages.mount - Huge Pages File System...
73.033          Mounting dev-mqueue.mount - POSIX Message Queue File System...
73.033          Mounting sys-kernel-debug.mount - Kernel Debug File System...
73.053          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
73.074          Starting systemd-journald.service - Journal Service...
73.094          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
73.094          Starting modprobe@configfs.service - Load Kernel Module configfs...
73.115          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
73.115          Starting modprobe@drm.service - Load Kernel Module drm...
73.136          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
73.136          Starting modprobe@fuse.service - Load Kernel Module fuse...
73.156          Starting modprobe@loop.service - Load Kernel Module loop...
73.218          Starting systemd-modules-load.service - Load Kernel Modules...
73.218          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
73.259          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
73.259 [  OK  ] Started systemd-journald.service - Journal Service.
73.259 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
73.279 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
73.279 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
73.279 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
73.300 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
73.449 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
73.634 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
73.675 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
73.696 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
73.696 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
73.717 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
73.717 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
73.758          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
73.758          Mounting sys-kernel-config.mount - Kernel Configuration File System...
73.779          Starting systemd-sysctl.service - Apply Kernel Variables...
73.799          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
73.799 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
73.799 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
73.820 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
73.861          Starting systemd-random-seed.service - Load/Save OS Random Seed...
73.881 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
73.902 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
73.923 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
73.943          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
73.964 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
73.964 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
73.984          Mounting tmp.mount - /tmp...
74.005          Mounting var-cache.mount - /var/cache...
74.005          Mounting var-log.mount - /var/log...
74.025          Mounting var-tmp.mount - /var/tmp...
74.046          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
74.046 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
74.046 [  OK  ] Mounted tmp.mount - /tmp.
74.066 [  OK  ] Mounted var-cache.mount - /var/cache.
74.066 [  OK  ] Mounted var-log.mount - /var/log.
74.066 [  OK  ] Mounted var-tmp.mount - /var/tmp.
74.066 [  OK  ] Reached target local-fs.target - Local File Systems.
74.087 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
74.087 [  OK  ] Reached target sockets.target - Socket Units.
74.107          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
74.128 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
74.128          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
74.189 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
74.189          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
74.251 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
74.600 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
74.600 [  OK  ] Reached target sysinit.target - System Initialization.
74.600 [  OK  ] Started apt-daily.timer - Daily apt download activities.
74.600 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
74.621 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
74.621 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
74.621 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
74.621 [  OK  ] Started motd-news.timer - Message of the Day.
74.621 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
74.641 [  OK  ] Reached target timers.target - Timer Units.
74.641 [  OK  ] Reached target basic.target - Basic System.
74.662          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
74.683          Starting getty-static.service - geâ¦bus and logind are not available...
74.724          Starting systemd-user-sessions.service - Permit User Sessions...
74.766          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
74.807 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
74.828 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
74.869 [  OK  ] Started getty@tty1.service - Getty on tty1.
74.910 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
74.910 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
74.951 [  OK  ] Started getty@tty2.service - Getty on tty2.
75.033 [  OK  ] Started getty@tty3.service - Getty on tty3.
75.054 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
75.054 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
75.054 [  OK  ] Started getty@tty4.service - Getty on tty4.
75.074 [  OK  ] Started getty@tty5.service - Getty on tty5.
75.095 [  OK  ] Started getty@tty6.service - Getty on tty6.
75.095 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
75.115 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
75.115 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
75.156 [  OK  ] Reached target getty.target - Login Prompts.
75.177 [  OK  ] Reached target multi-user.target - Multi-User System.
75.177 [  OK  ] Reached target graphical.target - Graphical Interface.
75.198          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
75.218 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
