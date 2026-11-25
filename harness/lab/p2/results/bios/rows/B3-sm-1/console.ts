# tailts start epoch=1795463468.926
0.103 iPXE initialising devices...
0.226 
0.226 
0.246 
0.246 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
0.267 Features: DNS HTTP iSCSI TFTP SRP AoE ELF MBOOT PXE bzImage Menu PXEXT
0.267 WRRUN-STUB
3.376 Configuring (net0 52:54:00:77:11:4a)...... ok
3.396 tftp://10.0.2.2/autoexec.ipxe... ok
3.396 WRRUN-BEGIN row=B3
3.437 Waiting for link-up on net1... ok
3.437 WRRUN-NET-OK
3.437 WRRUN-SAN-START sanboot
3.457 rbd: stack monitor: the stack is not iPXE's own (frame 0x7ffd55a8, internal stack 0xffffffffeb547e30 to 0xffffffffeb549e30): not painted
3.661 Registered SAN device 0x80
3.682 Booting from SAN device 0x80
3.744 rbd: stack monitor: the stack is not iPXE's own (frame 0x7ffd5228, internal stack 0xffffffffeb547e30 to 0xffffffffeb549e30): not painted
4.912 GNU GRUB  version 2.14
4.912 
4.932 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
4.932       Press enter to boot the selected OS, `e' to edit the commands       
11.283       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
11.324 Starting systemd-udevd version 255.4-1ubuntu8.19
11.875 Begin: Loading essential drivers ... done.
11.875 Begin: Running /scripts/init-premount ... done.
11.895 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
11.916 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
12.160 RBFT-HOOK table found by source scan
12.160 RBFT-HOOK nic: eth1 has MAC 52:54:00:77:12:ca
12.181 RBFT-HOOK nic: eth1 address 10.77.0.74/24
12.181 RBFT-HOOK table check (source scan):
12.425 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
12.425 RBFT PASS signature: rBFT
12.425 RBFT PASS length: 234 bytes
12.425 RBFT PASS acpi_revision: 1
12.425 RBFT PASS checksum: all 234 bytes sum to 0
12.446 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
12.446 RBFT PASS magic: WRBT
12.446 RBFT PASS version: 1
12.446 RBFT PASS header_len: 116
12.446 RBFT PASS reserved: all reserved bytes are zero
12.446 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
12.446 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
12.446 RBFT PASS namespace: absent (as in version 1)
12.446 RBFT PASS rules: every rule of the field table holds
12.446 RBFT PASS entity: wrtest-p2-b3
12.446 RBFT PASS pool: winrbd
12.446 RBFT PASS image: wrtest-p2-b3
12.446 RBFT PASS image_id: 39648e0b332d
12.446 RBFT PASS snapshot: absent, as expected
12.446 RBFT PASS auth: cephx
12.446 RBFT PASS msgr_mode: crc
12.467 RBFT PASS flags: key,static (0x6)
12.467 RBFT PASS flag_readonly: clear
12.467 RBFT PASS flag_key: set
12.467 RBFT PASS flag_nic_static: set
12.467 RBFT PASS flag_vlan: clear
12.467 RBFT PASS flag_fsid: clear
12.467 RBFT PASS flag_secure_required: clear
12.467 RBFT PASS key_type: aes
12.467 RBFT PASS key_len: 16
12.467 RBFT INFO key: present in the table (aes, 16 bytes), not printed
12.467 RBFT PASS mon_count: 1
12.467 RBFT PASS mon0: 10.77.0.10:3300
12.467 RBFT PASS fsid: none, as expected
12.467 RBFT PASS nic_mac: 52:54:00:77:12:ca
12.467 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:ca exists in this guest
12.467 RBFT PASS nic_vlan: 0
12.467 RBFT PASS nic_mtu: 1500
12.467 RBFT PASS nic_family: 4
12.487 RBFT PASS nic_ip: 10.77.0.74
12.487 RBFT PASS nic_prefix: 24
12.487 RBFT PASS nic_gateway: zero, as expected
12.487 RBFT PASS nic_dns: zero, as expected
12.487 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 a1 46 45 4e 53 59 53
12.487 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
12.487 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
12.487 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
12.487 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 ca 00 00
12.487 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 4a 00 00 00 00 00 00 00 00
12.487 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
12.487 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
12.487 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
12.508 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
12.508 RBFT DUMP 00a0: 32 2d 62 33 00 77 69 6e 72 62 64 00 77 72 74 65
12.508 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 33 00 33 39 36 34 38 65 30
12.508 RBFT DUMP 00c0: 62 33 33 32 64 00 04 00 e4 0c 0a 4d 00 0a 00 00
12.508 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
12.508 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
12.508 RBFT-RESULT PASS pass=40 fail=0 skip=0
12.508 WRBOOT-TABLE PASS
12.569 RBFT-HOOK map: pool winrbd image wrtest-p2-b3 via 10.77.0.10:3300 as client.wrtest-p2-b3 (options ms_mode=crc,noshare, the key is not shown)
12.651 RBFT-HOOK map: image winrbd/wrtest-p2-b3 is /dev/rbd0, root device /dev/rbd0p1
12.651 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
12.651 done.
12.671 Begin: Running /scripts/local-premount ... done.
42.743 Warning: fsck not present, so skipping root file system
42.784 done.
42.910 Begin: Running /scripts/local-bottom ... done.
42.930 Begin: Running /scripts/init-bottom ... done.
44.064 
44.064 Welcome to Ubuntu 24.04 LTS!
44.064 
44.880 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
44.901 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
44.901 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
44.901 [  OK  ] Created slice user.slice - User and Session Slice.
44.901 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
44.901 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
44.921 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
44.921          Expecting device dev-ttyS0.device - /dev/ttyS0...
44.921 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
44.921 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
44.921 [  OK  ] Reached target paths.target - Path Units.
44.921 [  OK  ] Reached target remote-fs.target - Remote File Systems.
44.921 [  OK  ] Reached target slices.target - Slice Units.
44.921 [  OK  ] Reached target swap.target - Swaps.
44.942 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
44.942 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
44.942 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
44.942 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
44.942 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
44.963 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
44.963          Mounting dev-hugepages.mount - Huge Pages File System...
44.983          Mounting dev-mqueue.mount - POSIX Message Queue File System...
44.983          Mounting sys-kernel-debug.mount - Kernel Debug File System...
45.004          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
45.004          Starting systemd-journald.service - Journal Service...
45.024          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
45.024          Starting modprobe@configfs.service - Load Kernel Module configfs...
45.044          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
45.065          Starting modprobe@drm.service - Load Kernel Module drm...
45.086          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
45.106          Starting modprobe@fuse.service - Load Kernel Module fuse...
45.127          Starting modprobe@loop.service - Load Kernel Module loop...
45.147          Starting systemd-modules-load.service - Load Kernel Modules...
45.147          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
45.147          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
45.168 [  OK  ] Started systemd-journald.service - Journal Service.
45.168 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
45.168 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
45.188 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
45.188 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
45.188 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
45.188 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
45.209 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
45.209 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
45.229 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
45.229 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
45.250 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
45.250 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
45.270 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
45.291          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
45.311          Mounting sys-kernel-config.mount - Kernel Configuration File System...
45.332          Starting systemd-random-seed.service - Load/Save OS Random Seed...
45.332          Starting systemd-sysctl.service - Apply Kernel Variables...
45.353          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
45.353 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
45.373 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
45.373 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
45.478 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
45.499 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
45.519 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
45.519          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
45.561 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
45.561 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
45.581          Mounting tmp.mount - /tmp...
45.581          Mounting var-cache.mount - /var/cache...
45.581          Mounting var-log.mount - /var/log...
45.622          Mounting var-tmp.mount - /var/tmp...
45.622          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
45.622 [  OK  ] Mounted tmp.mount - /tmp.
45.643 [  OK  ] Mounted var-cache.mount - /var/cache.
45.643 [  OK  ] Mounted var-log.mount - /var/log.
45.643 [  OK  ] Mounted var-tmp.mount - /var/tmp.
45.643 [  OK  ] Reached target local-fs.target - Local File Systems.
45.664 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
45.664 [  OK  ] Reached target sockets.target - Socket Units.
45.684          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
45.705 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
45.725          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
45.766 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
45.850          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
45.891 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
45.912 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
45.912 [  OK  ] Reached target sysinit.target - System Initialization.
45.912 [  OK  ] Started apt-daily.timer - Daily apt download activities.
45.912 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
45.912 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
45.933 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
45.933 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
45.933 [  OK  ] Started motd-news.timer - Message of the Day.
45.933 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
45.933 [  OK  ] Reached target timers.target - Timer Units.
45.933 [  OK  ] Reached target basic.target - Basic System.
45.954          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
45.974          Starting getty-static.service - geâ¦bus and logind are not available...
45.995          Starting systemd-user-sessions.service - Permit User Sessions...
46.016          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
46.036 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
46.118 [  OK  ] Started getty@tty1.service - Getty on tty1.
46.139 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
46.201 [  OK  ] Started getty@tty2.service - Getty on tty2.
46.282 [  OK  ] Started getty@tty3.service - Getty on tty3.
46.282 WRBOOT-NET eth0 mac=52:54:00:77:11:4a 
46.303 WRBOOT-NET eth1 mac=52:54:00:77:12:ca 10.77.0.74/24 fe80::5054:ff:fe77:12ca/64 
46.303 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b3 kernel=6.8.0-151-generic
46.323 [  OK  ] Started getty@tty4.service - Getty on tty4.
46.323 [  OK  ] Started getty@tty5.service - Getty on tty5.
46.344 [  OK  ] Started getty@tty6.service - Getty on tty6.
46.364 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
46.385 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
46.385 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
46.426 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
46.468 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
46.468 [  OK  ] Reached target getty.target - Login Prompts.
46.468 [  OK  ] Reached target multi-user.target - Multi-User System.
46.468 [  OK  ] Reached target graphical.target - Graphical Interface.
46.488          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
46.509 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
