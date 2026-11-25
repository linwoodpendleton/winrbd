# tailts start epoch=1795464646.026
8.004 iPXE initialising devices...
8.024 
8.045 
8.066 
8.107 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.128 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.148 WRRUN-STUB
11.316 Configuring (net0 52:54:00:77:12:c7)...... ok
11.336 tftp://10.77.0.10/autoexec.ipxe... ok
11.378 WRRUN-BEGIN row=B1
11.418 Waiting for link-up on net0... ok
11.439 WRRUN-NET-OK
11.460 WRRUN-SAN-START sanboot
11.788 Registered SAN device 0x80
11.808 Booting from SAN device 0x80
13.362 GNU GRUB  version 2.14
13.362 
13.383 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.404       Press enter to boot the selected OS, `e' to edit the commands       
81.973       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 rbd: the cluster has not answered for 30 seconds, closing the path: operation timed out (WR_E_TIMEOUT)
138.314 Loading, please wait...
138.335 Starting systemd-udevd version 255.4-1ubuntu8.19
139.320 Begin: Loading essential drivers ... done.
139.320 Begin: Running /scripts/init-premount ... done.
139.361 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
139.361 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
140.897 RBFT-HOOK table found by source scan
140.940 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
140.940 RBFT-HOOK nic: eth0 address 10.77.0.71/24
140.940 RBFT-HOOK table check (source scan):
142.345 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
142.345 RBFT PASS signature: rBFT
142.345 RBFT PASS length: 234 bytes
142.366 RBFT PASS acpi_revision: 1
142.366 RBFT PASS checksum: all 234 bytes sum to 0
142.366 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
142.366 RBFT PASS magic: WRBT
142.366 RBFT PASS version: 1
142.366 RBFT PASS header_len: 116
142.510 RBFT PASS reserved: all reserved bytes are zero
142.531 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
142.733 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
142.978 RBFT PASS namespace: absent (as in version 1)
142.978 RBFT PASS rules: every rule of the field table holds
142.978 RBFT PASS entity: wrtest-p2-b1
142.999 RBFT PASS pool: winrbd
142.999 RBFT PASS image: wrtest-p2-b1
143.019 RBFT PASS image_id: 38d9a2e0bcec
143.121 RBFT PASS snapshot: absent, as expected
143.142 RBFT PASS auth: cephx
143.203 RBFT PASS msgr_mode: crc
143.224 RBFT PASS flags: key,static (0x6)
143.244 RBFT PASS flag_readonly: clear
143.244 RBFT PASS flag_key: set
143.244 RBFT PASS flag_nic_static: set
143.244 RBFT PASS flag_vlan: clear
143.244 RBFT PASS flag_fsid: clear
143.244 RBFT PASS flag_secure_required: clear
143.244 RBFT PASS key_type: aes
143.265 RBFT PASS key_len: 16
143.265 RBFT INFO key: present in the table (aes, 16 bytes), not printed
143.265 RBFT PASS mon_count: 1
143.265 RBFT PASS mon0: 10.77.0.10:3300
143.265 RBFT PASS fsid: none, as expected
143.265 RBFT PASS nic_mac: 52:54:00:77:12:c7
143.348 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
143.348 RBFT PASS nic_vlan: 0
143.348 RBFT PASS nic_mtu: 1500
143.348 RBFT PASS nic_family: 4
143.348 RBFT PASS nic_ip: 10.77.0.71
143.348 RBFT PASS nic_prefix: 24
143.348 RBFT PASS nic_gateway: zero, as expected
143.348 RBFT PASS nic_dns: zero, as expected
143.348 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
143.369 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
143.369 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
143.369 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
143.431 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
143.616 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
143.741 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
144.277 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
144.340 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
144.340 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
144.340 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
144.340 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
144.361 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
144.361 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
144.361 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
144.361 RBFT-RESULT PASS pass=40 fail=0 skip=0
144.361 WRBOOT-TABLE PASS
144.962 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
145.188 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
145.188 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
145.188 done.
145.209 Begin: Running /scripts/local-premount ... done.
175.337 Warning: fsck not present, so skipping root file system
175.358 done.
175.400 Begin: Running /scripts/local-bottom ... done.
175.400 Begin: Running /scripts/init-bottom ... done.
177.679 
177.702 Welcome to Ubuntu 24.04 LTS!
177.702 
179.236 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
179.257 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
179.257 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
179.257 [  OK  ] Created slice user.slice - User and Session Slice.
179.257 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
179.257 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
179.278 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
179.278          Expecting device dev-ttyS0.device - /dev/ttyS0...
179.278 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
179.278 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
179.278 [  OK  ] Reached target paths.target - Path Units.
179.299 [  OK  ] Reached target remote-fs.target - Remote File Systems.
179.299 [  OK  ] Reached target slices.target - Slice Units.
179.299 [  OK  ] Reached target swap.target - Swaps.
179.299 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
179.299 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
179.299 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
179.319 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
179.319 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
179.319 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
179.340          Mounting dev-hugepages.mount - Huge Pages File System...
179.360          Mounting dev-mqueue.mount - POSIX Message Queue File System...
179.360          Mounting sys-kernel-debug.mount - Kernel Debug File System...
179.381          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
179.381          Starting systemd-journald.service - Journal Service...
179.402          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
179.423          Starting modprobe@configfs.service - Load Kernel Module configfs...
179.443          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
179.464          Starting modprobe@drm.service - Load Kernel Module drm...
179.837          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
179.837          Starting modprobe@fuse.service - Load Kernel Module fuse...
179.857          Starting modprobe@loop.service - Load Kernel Module loop...
179.878          Starting systemd-modules-load.service - Load Kernel Modules...
179.899          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
179.919          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
179.919 [  OK  ] Started systemd-journald.service - Journal Service.
179.940 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
179.940 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
179.940 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
179.940 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
179.961 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
179.961 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
179.961 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
179.981 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
179.981 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
180.002 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
180.002 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
180.002 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
180.043          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
180.063          Mounting sys-kernel-config.mount - Kernel Configuration File System...
180.084          Starting systemd-sysctl.service - Apply Kernel Variables...
180.105          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
180.125 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
180.125 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
180.125 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
180.166          Starting systemd-random-seed.service - Load/Save OS Random Seed...
180.207 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
180.228 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
180.269 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
180.269          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
180.309 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
180.309 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
180.330          Mounting tmp.mount - /tmp...
180.330          Mounting var-cache.mount - /var/cache...
180.351          Mounting var-log.mount - /var/log...
180.351          Mounting var-tmp.mount - /var/tmp...
180.372          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
180.393 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
180.393 [  OK  ] Mounted tmp.mount - /tmp.
180.393 [  OK  ] Mounted var-cache.mount - /var/cache.
180.393 [  OK  ] Mounted var-log.mount - /var/log.
180.393 [  OK  ] Mounted var-tmp.mount - /var/tmp.
180.413 [  OK  ] Reached target local-fs.target - Local File Systems.
180.413 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
180.413 [  OK  ] Reached target sockets.target - Socket Units.
180.434          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
180.743 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
180.764          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
180.847 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
180.868          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
180.929 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
181.011 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
181.032 [  OK  ] Reached target sysinit.target - System Initialization.
181.032 [  OK  ] Started apt-daily.timer - Daily apt download activities.
181.032 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
181.032 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
181.032 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
181.032 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
181.052 [  OK  ] Started motd-news.timer - Message of the Day.
181.052 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
181.052 [  OK  ] Reached target timers.target - Timer Units.
181.052 [  OK  ] Reached target basic.target - Basic System.
181.073          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
181.073          Starting getty-static.service - geâ¦bus and logind are not available...
181.093          Starting systemd-user-sessions.service - Permit User Sessions...
181.135          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
181.176 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
181.197 [  OK  ] Started getty@tty1.service - Getty on tty1.
181.279 [  OK  ] Started getty@tty2.service - Getty on tty2.
181.300 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
181.300 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
181.361 [  OK  ] Started getty@tty3.service - Getty on tty3.
181.382 [  OK  ] Started getty@tty4.service - Getty on tty4.
181.403 [  OK  ] Started getty@tty5.service - Getty on tty5.
181.424 [  OK  ] Started getty@tty6.service - Getty on tty6.
181.444 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
181.465 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
181.671 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
181.671 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
181.692 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
181.712 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
181.733 [  OK  ] Reached target getty.target - Login Prompts.
181.733 [  OK  ] Reached target multi-user.target - Multi-User System.
181.754 [  OK  ] Reached target graphical.target - Graphical Interface.
181.754          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
181.795 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
