# tailts start epoch=1795464323.342
7.803 iPXE initialising devices...
7.844 
7.865 
7.885 
7.906 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.926 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.947 WRRUN-STUB
11.069 Configuring (net0 52:54:00:77:12:c7)...... ok
11.110 tftp://10.77.0.10/autoexec.ipxe... ok
11.110 WRRUN-BEGIN row=B1
11.192 Waiting for link-up on net0... ok
11.212 WRRUN-NET-OK
11.212 WRRUN-SAN-START sanboot
11.254 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.274 rbd: core stack high-water 512 of 16384 bytes
11.295 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.315 rbd: core stack high-water 788 of 16384 bytes
11.335 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.356 rbd: core stack high-water 1304 of 16384 bytes
11.397 rbd: stack high-water 2096 of 4096 bytes (2000 left)
11.417 rbd: core stack high-water 1588 of 16384 bytes
11.846 Registered SAN device 0x80
11.866 Booting from SAN device 0x80
11.887 rbd: stack high-water 2784 of 4096 bytes (1312 left)
11.907 rbd: core stack high-water 1696 of 16384 bytes
13.607 GNU GRUB  version 2.14
13.607 
13.627 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.627       Press enter to boot the selected OS, `e' to edit the commands       
26.857       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
26.898 Starting systemd-udevd version 255.4-1ubuntu8.19
27.530 Begin: Loading essential drivers ... done.
27.653 Begin: Running /scripts/init-premount ... done.
27.673 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
27.673 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
27.939 RBFT-HOOK table found by source scan
27.939 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
27.960 RBFT-HOOK nic: eth0 address 10.77.0.71/24
27.960 RBFT-HOOK table check (source scan):
28.245 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
28.245 RBFT PASS signature: rBFT
28.245 RBFT PASS length: 234 bytes
28.245 RBFT PASS acpi_revision: 1
28.245 RBFT PASS checksum: all 234 bytes sum to 0
28.245 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
28.266 RBFT PASS magic: WRBT
28.266 RBFT PASS version: 1
28.266 RBFT PASS header_len: 116
28.266 RBFT PASS reserved: all reserved bytes are zero
28.266 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
28.266 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
28.266 RBFT PASS namespace: absent (as in version 1)
28.266 RBFT PASS rules: every rule of the field table holds
28.266 RBFT PASS entity: wrtest-p2-b1
28.266 RBFT PASS pool: winrbd
28.286 RBFT PASS image: wrtest-p2-b1
28.286 RBFT PASS image_id: 38d9a2e0bcec
28.286 RBFT PASS snapshot: absent, as expected
28.286 RBFT PASS auth: cephx
28.286 RBFT PASS msgr_mode: crc
28.286 RBFT PASS flags: key,static (0x6)
28.286 RBFT PASS flag_readonly: clear
28.286 RBFT PASS flag_key: set
28.286 RBFT PASS flag_nic_static: set
28.286 RBFT PASS flag_vlan: clear
28.286 RBFT PASS flag_fsid: clear
28.286 RBFT PASS flag_secure_required: clear
28.286 RBFT PASS key_type: aes
28.286 RBFT PASS key_len: 16
28.286 RBFT INFO key: present in the table (aes, 16 bytes), not printed
28.307 RBFT PASS mon_count: 1
28.307 RBFT PASS mon0: 10.77.0.10:3300
28.307 RBFT PASS fsid: none, as expected
28.307 RBFT PASS nic_mac: 52:54:00:77:12:c7
28.307 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
28.307 RBFT PASS nic_vlan: 0
28.307 RBFT PASS nic_mtu: 1500
28.307 RBFT PASS nic_family: 4
28.307 RBFT PASS nic_ip: 10.77.0.71
28.307 RBFT PASS nic_prefix: 24
28.307 RBFT PASS nic_gateway: zero, as expected
28.307 RBFT PASS nic_dns: zero, as expected
28.307 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 37 46 45 4e 53 59 53
28.307 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
28.328 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
28.328 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
28.328 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
28.328 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
28.328 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
28.328 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
28.328 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
28.328 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
28.328 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
28.328 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
28.328 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
28.348 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
28.348 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
28.348 RBFT-RESULT PASS pass=40 fail=0 skip=0
28.348 WRBOOT-TABLE PASS
28.389 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
28.739 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
28.739 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
28.739 done.
28.759 Begin: Running /scripts/local-premount ... done.
63.904 Warning: fsck not present, so skipping root file system
63.945 done.
63.987 Begin: Running /scripts/local-bottom ... done.
64.007 Begin: Running /scripts/init-bottom ... done.
65.963 
65.963 Welcome to Ubuntu 24.04 LTS!
65.963 
68.271 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
68.292 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
68.292 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
68.292 [  OK  ] Created slice user.slice - User and Session Slice.
68.292 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
68.292 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
68.313 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
68.334          Expecting device dev-ttyS0.device - /dev/ttyS0...
68.355 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
68.355 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
68.355 [  OK  ] Reached target paths.target - Path Units.
68.355 [  OK  ] Reached target remote-fs.target - Remote File Systems.
68.355 [  OK  ] Reached target slices.target - Slice Units.
68.355 [  OK  ] Reached target swap.target - Swaps.
68.376 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
68.376 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
68.376 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
68.376 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
68.397 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
68.397 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
68.417          Mounting dev-hugepages.mount - Huge Pages File System...
68.439          Mounting dev-mqueue.mount - POSIX Message Queue File System...
68.459          Mounting sys-kernel-debug.mount - Kernel Debug File System...
68.480          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
68.648          Starting systemd-journald.service - Journal Service...
68.690          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
68.711          Starting modprobe@configfs.service - Load Kernel Module configfs...
68.711          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
68.731          Starting modprobe@drm.service - Load Kernel Module drm...
68.752          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
68.773          Starting modprobe@fuse.service - Load Kernel Module fuse...
68.773          Starting modprobe@loop.service - Load Kernel Module loop...
68.794          Starting systemd-modules-load.service - Load Kernel Modules...
68.815          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
68.898          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
68.919 [  OK  ] Started systemd-journald.service - Journal Service.
68.919 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
68.919 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
69.010 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
69.010 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
69.010 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
69.031 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
69.031 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
69.051 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
69.051 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
69.051 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
69.072 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
69.072 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
69.114          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
69.135          Mounting sys-kernel-config.mount - Kernel Configuration File System...
69.135          Starting systemd-sysctl.service - Apply Kernel Variables...
69.156          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
69.177 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
69.177 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
69.197 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
69.239          Starting systemd-random-seed.service - Load/Save OS Random Seed...
69.280 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
69.301 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
69.342 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
69.363          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
69.383 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
69.383 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
69.404          Mounting tmp.mount - /tmp...
69.425          Mounting var-cache.mount - /var/cache...
69.466          Mounting var-log.mount - /var/log...
69.466          Mounting var-tmp.mount - /var/tmp...
69.693          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
69.714 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
69.714 [  OK  ] Mounted tmp.mount - /tmp.
69.714 [  OK  ] Mounted var-cache.mount - /var/cache.
69.735 [  OK  ] Mounted var-log.mount - /var/log.
69.735 [  OK  ] Mounted var-tmp.mount - /var/tmp.
69.755 [  OK  ] Reached target local-fs.target - Local File Systems.
69.776 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
69.776 [  OK  ] Reached target sockets.target - Socket Units.
69.797          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
69.889 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
69.909          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
69.992 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
70.013          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
70.054 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
70.054 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
70.075 [  OK  ] Reached target sysinit.target - System Initialization.
70.075 [  OK  ] Started apt-daily.timer - Daily apt download activities.
70.075 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
70.075 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
70.075 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
70.096 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
70.096 [  OK  ] Started motd-news.timer - Message of the Day.
70.096 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
70.096 [  OK  ] Reached target timers.target - Timer Units.
70.096 [  OK  ] Reached target basic.target - Basic System.
70.117          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
70.158          Starting getty-static.service - geâ¦bus and logind are not available...
70.179          Starting systemd-user-sessions.service - Permit User Sessions...
70.221          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
70.244 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
70.265 [  OK  ] Started getty@tty1.service - Getty on tty1.
70.307 [  OK  ] Started getty@tty2.service - Getty on tty2.
70.328 [  OK  ] Started getty@tty3.service - Getty on tty3.
70.328 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
70.369 [  OK  ] Started getty@tty4.service - Getty on tty4.
70.369 [  OK  ] Started getty@tty5.service - Getty on tty5.
70.389 [  OK  ] Started getty@tty6.service - Getty on tty6.
70.410 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
70.410 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
70.410 [  OK  ] Reached target getty.target - Login Prompts.
70.867 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
70.908 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
71.052 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
71.052 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
71.073 [  OK  ] Listening on systemd-rfkill.socketâ¦ll Switch Status /dev/rfkill Watch.
71.073 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
71.073 [  OK  ] Reached target multi-user.target - Multi-User System.
71.073 [  OK  ] Reached target graphical.target - Graphical Interface.
71.093          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
71.135 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
