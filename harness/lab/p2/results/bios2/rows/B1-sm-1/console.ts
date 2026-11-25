# tailts start epoch=1795481836.642
7.836 iPXE initialising devices...
7.857 
7.878 
7.899 
7.920 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
7.966 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
7.987 WRRUN-STUB
11.115 Configuring (net0 52:54:00:77:12:c7)...... ok
11.157 tftp://10.77.0.10/autoexec.ipxe... ok
11.178 WRRUN-BEGIN row=B1
11.220 Waiting for link-up on net0... ok
11.241 WRRUN-NET-OK
11.262 WRRUN-SAN-START sanboot
11.325 rbd: stack monitor: the stack is not iPXE's own (frame 0x7fe8edd8, internal stack 0xffffffffeb464660 to 0xffffffffeb466660): not painted
11.554 Registered SAN device 0x80
11.575 Booting from SAN device 0x80
11.783 rbd: stack monitor: the stack is not iPXE's own (frame 0x7fe8ea58, internal stack 0xffffffffeb464660 to 0xffffffffeb466660): not painted
14.439 GNU GRUB  version 2.14
14.439 
14.460 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.481       Press enter to boot the selected OS, `e' to edit the commands       
27.012       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
27.055 Starting systemd-udevd version 255.4-1ubuntu8.19
27.614 Begin: Loading essential drivers ... done.
27.614 Begin: Running /scripts/init-premount ... done.
27.635 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
27.656 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
27.987 RBFT-HOOK table found by source scan
27.987 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
27.987 RBFT-HOOK nic: eth0 address 10.77.0.71/24
28.008 RBFT-HOOK table check (source scan):
28.255 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
28.255 RBFT PASS signature: rBFT
28.255 RBFT PASS length: 234 bytes
28.255 RBFT PASS acpi_revision: 1
28.255 RBFT PASS checksum: all 234 bytes sum to 0
28.255 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
28.276 RBFT PASS magic: WRBT
28.276 RBFT PASS version: 1
28.276 RBFT PASS header_len: 116
28.276 RBFT PASS reserved: all reserved bytes are zero
28.276 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
28.276 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
28.276 RBFT PASS namespace: absent (as in version 1)
28.276 RBFT PASS rules: every rule of the field table holds
28.276 RBFT PASS entity: wrtest-p2-b1
28.276 RBFT PASS pool: winrbd
28.276 RBFT PASS image: wrtest-p2-b1
28.276 RBFT PASS image_id: 3fae3418fe30
28.276 RBFT PASS snapshot: absent, as expected
28.276 RBFT PASS auth: cephx
28.276 RBFT PASS msgr_mode: crc
28.276 RBFT PASS flags: key,static (0x6)
28.276 RBFT PASS flag_readonly: clear
28.276 RBFT PASS flag_key: set
28.276 RBFT PASS flag_nic_static: set
28.276 RBFT PASS flag_vlan: clear
28.276 RBFT PASS flag_fsid: clear
28.297 RBFT PASS flag_secure_required: clear
28.297 RBFT PASS key_type: aes
28.297 RBFT PASS key_len: 16
28.297 RBFT INFO key: present in the table (aes, 16 bytes), not printed
28.297 RBFT PASS mon_count: 1
28.297 RBFT PASS mon0: 10.77.0.10:3300
28.297 RBFT PASS fsid: none, as expected
28.297 RBFT PASS nic_mac: 52:54:00:77:12:c7
28.297 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
28.297 RBFT PASS nic_vlan: 0
28.297 RBFT PASS nic_mtu: 1500
28.297 RBFT PASS nic_family: 4
28.297 RBFT PASS nic_ip: 10.77.0.71
28.297 RBFT PASS nic_prefix: 24
28.297 RBFT PASS nic_gateway: zero, as expected
28.297 RBFT PASS nic_dns: zero, as expected
28.297 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
28.297 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
28.297 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
28.319 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
28.319 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
28.319 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
28.319 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
28.319 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
28.319 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
28.319 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
28.319 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
28.319 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
28.319 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
28.319 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
28.319 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
28.319 RBFT-RESULT PASS pass=40 fail=0 skip=0
28.319 WRBOOT-TABLE PASS
28.403 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
28.466 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
28.466 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
28.466 done.
28.488 Begin: Running /scripts/local-premount ... done.
58.572 Warning: fsck not present, so skipping root file system
58.593 done.
58.614 Begin: Running /scripts/local-bottom ... done.
58.635 Begin: Running /scripts/init-bottom ... done.
59.907 
59.907 Welcome to Ubuntu 24.04 LTS!
59.907 
60.805 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
60.805 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
60.805 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
60.826 [  OK  ] Created slice user.slice - User and Session Slice.
60.826 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
60.826 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
60.826 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
60.826          Expecting device dev-ttyS0.device - /dev/ttyS0...
60.826 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
60.846 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
60.846 [  OK  ] Reached target paths.target - Path Units.
60.846 [  OK  ] Reached target remote-fs.target - Remote File Systems.
60.846 [  OK  ] Reached target slices.target - Slice Units.
60.846 [  OK  ] Reached target swap.target - Swaps.
60.846 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
60.867 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
60.867 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
60.867 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
60.867 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
60.888 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
60.908          Mounting dev-hugepages.mount - Huge Pages File System...
60.929          Mounting dev-mqueue.mount - POSIX Message Queue File System...
60.929          Mounting sys-kernel-debug.mount - Kernel Debug File System...
60.950          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
60.970          Starting systemd-journald.service - Journal Service...
60.991          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
61.012          Starting modprobe@configfs.service - Load Kernel Module configfs...
61.033          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
61.054          Starting modprobe@drm.service - Load Kernel Module drm...
61.075          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
61.096          Starting modprobe@fuse.service - Load Kernel Module fuse...
61.096          Starting modprobe@loop.service - Load Kernel Module loop...
61.117          Starting systemd-modules-load.service - Load Kernel Modules...
61.137          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
61.158          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
61.158 [  OK  ] Started systemd-journald.service - Journal Service.
61.179 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
61.179 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
61.179 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
61.200 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
61.200 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
61.221 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
61.221 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
61.242 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
61.242 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
61.263 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
61.263 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
61.284 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
61.326          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
61.326          Mounting sys-kernel-config.mount - Kernel Configuration File System...
61.348          Starting systemd-sysctl.service - Apply Kernel Variables...
61.368          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
61.397 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
61.397 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
61.397 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
61.439          Starting systemd-random-seed.service - Load/Save OS Random Seed...
61.501 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
61.522 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
61.544 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
61.565          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
61.586 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
61.607 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
61.607 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
61.629          Mounting tmp.mount - /tmp...
61.650          Mounting var-cache.mount - /var/cache...
61.671          Mounting var-log.mount - /var/log...
61.671          Mounting var-tmp.mount - /var/tmp...
61.692          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
61.692 [  OK  ] Mounted tmp.mount - /tmp.
61.692 [  OK  ] Mounted var-cache.mount - /var/cache.
61.713 [  OK  ] Mounted var-log.mount - /var/log.
61.713 [  OK  ] Mounted var-tmp.mount - /var/tmp.
61.713 [  OK  ] Reached target local-fs.target - Local File Systems.
61.734 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
61.734 [  OK  ] Reached target sockets.target - Socket Units.
61.755          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
61.798 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
61.798          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
61.860 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
61.881          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
61.923 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
61.923 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
61.923 [  OK  ] Reached target sysinit.target - System Initialization.
61.923 [  OK  ] Started apt-daily.timer - Daily apt download activities.
61.945 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
61.945 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
61.945 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
61.945 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
61.966 [  OK  ] Started motd-news.timer - Message of the Day.
61.966 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
61.966 [  OK  ] Reached target timers.target - Timer Units.
61.966 [  OK  ] Reached target basic.target - Basic System.
61.987          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
62.029          Starting getty-static.service - geâ¦bus and logind are not available...
62.050          Starting systemd-user-sessions.service - Permit User Sessions...
62.092          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
62.154 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
62.174 [  OK  ] Started getty@tty1.service - Getty on tty1.
62.236 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
62.339 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
62.359 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
62.359 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
62.380 [  OK  ] Started getty@tty2.service - Getty on tty2.
62.380 [  OK  ] Started getty@tty3.service - Getty on tty3.
62.401 [  OK  ] Started getty@tty4.service - Getty on tty4.
62.422 [  OK  ] Started getty@tty5.service - Getty on tty5.
62.463 [  OK  ] Started getty@tty6.service - Getty on tty6.
62.504 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
62.525 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
62.525 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
62.567 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
62.589 [  OK  ] Reached target getty.target - Login Prompts.
62.589 [  OK  ] Reached target multi-user.target - Multi-User System.
62.589 [  OK  ] Reached target graphical.target - Graphical Interface.
62.610          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
62.651 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
