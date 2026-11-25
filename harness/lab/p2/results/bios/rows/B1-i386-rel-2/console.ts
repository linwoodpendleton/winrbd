# tailts start epoch=1795465656.243
8.012 iPXE initialising devices...
8.033 
8.054 
8.054 
8.095 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.115 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.136 WRRUN-STUB
11.252 Configuring (net0 52:54:00:77:12:d6)...... ok
11.273 tftp://10.77.0.10/autoexec.ipxe... ok
11.293 WRRUN-BEGIN row=B1
11.355 Waiting for link-up on net0... ok
11.375 WRRUN-NET-OK
11.396 WRRUN-SAN-START sanboot
11.721 Registered SAN device 0x80
11.742 Booting from SAN device 0x80
13.737 GNU GRUB  version 2.14
13.737 
13.758 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
13.758       Press enter to boot the selected OS, `e' to edit the commands       
28.217       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
28.237 Starting systemd-udevd version 255.4-1ubuntu8.19
28.807 Begin: Loading essential drivers ... done.
28.807 Begin: Running /scripts/init-premount ... done.
28.848 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
28.848 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
29.114 RBFT-HOOK table found by source scan
29.114 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:d6
29.114 RBFT-HOOK nic: eth0 address 10.77.0.86/24
29.114 RBFT-HOOK table check (source scan):
29.358 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
29.358 RBFT PASS signature: rBFT
29.379 RBFT PASS length: 234 bytes
29.379 RBFT PASS acpi_revision: 1
29.379 RBFT PASS checksum: all 234 bytes sum to 0
29.379 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
29.379 RBFT PASS magic: WRBT
29.379 RBFT PASS version: 1
29.379 RBFT PASS header_len: 116
29.379 RBFT PASS reserved: all reserved bytes are zero
29.379 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
29.379 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
29.379 RBFT PASS namespace: absent (as in version 1)
29.379 RBFT PASS rules: every rule of the field table holds
29.379 RBFT PASS entity: wrtest-p2-b1
29.379 RBFT PASS pool: winrbd
29.379 RBFT PASS image: wrtest-p2-b1
29.399 RBFT PASS image_id: 38d9a2e0bcec
29.399 RBFT PASS snapshot: absent, as expected
29.399 RBFT PASS auth: cephx
29.399 RBFT PASS msgr_mode: crc
29.399 RBFT PASS flags: key,static (0x6)
29.399 RBFT PASS flag_readonly: clear
29.399 RBFT PASS flag_key: set
29.399 RBFT PASS flag_nic_static: set
29.399 RBFT PASS flag_vlan: clear
29.399 RBFT PASS flag_fsid: clear
29.399 RBFT PASS flag_secure_required: clear
29.399 RBFT PASS key_type: aes
29.399 RBFT PASS key_len: 16
29.399 RBFT INFO key: present in the table (aes, 16 bytes), not printed
29.399 RBFT PASS mon_count: 1
29.399 RBFT PASS mon0: 10.77.0.10:3300
29.399 RBFT PASS fsid: none, as expected
29.399 RBFT PASS nic_mac: 52:54:00:77:12:d6
29.420 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:d6 exists in this guest
29.420 RBFT PASS nic_vlan: 0
29.420 RBFT PASS nic_mtu: 1500
29.420 RBFT PASS nic_family: 4
29.420 RBFT PASS nic_ip: 10.77.0.86
29.420 RBFT PASS nic_prefix: 24
29.420 RBFT PASS nic_gateway: zero, as expected
29.420 RBFT PASS nic_dns: zero, as expected
29.420 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 19 46 45 4e 53 59 53
29.420 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
29.420 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
29.420 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
29.420 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 d6 00 00
29.420 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 56 00 00 00 00 00 00 00 00
29.441 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.441 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29.441 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
29.441 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
29.441 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
29.441 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 38 64 39 61 32 65
29.441 RBFT DUMP 00c0: 30 62 63 65 63 00 04 00 e4 0c 0a 4d 00 0a 00 00
29.441 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
29.441 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
29.441 RBFT-RESULT PASS pass=40 fail=0 skip=0
29.441 WRBOOT-TABLE PASS
29.502 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
29.563 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
29.563 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
29.563 done.
29.563 Begin: Running /scripts/local-premount ... done.
59.647 Warning: fsck not present, so skipping root file system
59.892 done.
59.912 Begin: Running /scripts/local-bottom ... done.
59.912 Begin: Running /scripts/init-bottom ... done.
61.013 
61.013 Welcome to Ubuntu 24.04 LTS!
61.013 
61.624 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
61.624 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
61.644 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
61.644 [  OK  ] Created slice user.slice - User and Session Slice.
61.644 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
61.644 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
61.644 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
61.665          Expecting device dev-ttyS0.device - /dev/ttyS0...
61.665 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
61.665 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
61.665 [  OK  ] Reached target paths.target - Path Units.
61.665 [  OK  ] Reached target remote-fs.target - Remote File Systems.
61.665 [  OK  ] Reached target slices.target - Slice Units.
61.665 [  OK  ] Reached target swap.target - Swaps.
61.665 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
61.686 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
61.686 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
61.686 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
61.686 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
61.686 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
61.706          Mounting dev-hugepages.mount - Huge Pages File System...
61.727          Mounting dev-mqueue.mount - POSIX Message Queue File System...
61.727          Mounting sys-kernel-debug.mount - Kernel Debug File System...
61.747          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
61.768          Starting systemd-journald.service - Journal Service...
61.768          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
61.789          Starting modprobe@configfs.service - Load Kernel Module configfs...
61.809          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
61.809          Starting modprobe@drm.service - Load Kernel Module drm...
61.830          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
61.830          Starting modprobe@fuse.service - Load Kernel Module fuse...
61.850          Starting modprobe@loop.service - Load Kernel Module loop...
61.871          Starting systemd-modules-load.service - Load Kernel Modules...
61.871          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
61.892          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
61.892 [  OK  ] Started systemd-journald.service - Journal Service.
61.892 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
61.912 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
61.912 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
61.912 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
61.912 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
61.933 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
61.933 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
61.954 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
61.954 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
61.975 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
61.975 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
61.975 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
61.995 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
62.036          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
62.036          Mounting sys-kernel-config.mount - Kernel Configuration File System...
62.057          Starting systemd-random-seed.service - Load/Save OS Random Seed...
62.077          Starting systemd-sysctl.service - Apply Kernel Variables...
62.098          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
62.098 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
62.118 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
62.118 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
62.159 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
62.221 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
62.241 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
62.241          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
62.262 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
62.262 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
62.282          Mounting tmp.mount - /tmp...
62.282          Mounting var-cache.mount - /var/cache...
62.303          Mounting var-log.mount - /var/log...
62.323          Mounting var-tmp.mount - /var/tmp...
62.323          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
62.348 [  OK  ] Mounted tmp.mount - /tmp.
62.348 [  OK  ] Mounted var-cache.mount - /var/cache.
62.348 [  OK  ] Mounted var-log.mount - /var/log.
62.348 [  OK  ] Mounted var-tmp.mount - /var/tmp.
62.368 [  OK  ] Reached target local-fs.target - Local File Systems.
62.368 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
62.368 [  OK  ] Reached target sockets.target - Socket Units.
62.389          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
62.409 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
62.409          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
62.471 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
62.492          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
62.512 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
62.553 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
62.553 [  OK  ] Reached target sysinit.target - System Initialization.
62.553 [  OK  ] Started apt-daily.timer - Daily apt download activities.
62.553 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
62.553 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
62.573 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
62.573 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
62.573 [  OK  ] Started motd-news.timer - Message of the Day.
62.573 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
62.573 [  OK  ] Reached target timers.target - Timer Units.
62.573 [  OK  ] Reached target basic.target - Basic System.
62.594          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
62.614          Starting getty-static.service - geâ¦bus and logind are not available...
62.635          Starting systemd-user-sessions.service - Permit User Sessions...
62.676          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
62.697 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
62.697 [  OK  ] Started getty@tty1.service - Getty on tty1.
62.738 [  OK  ] Started getty@tty2.service - Getty on tty2.
62.758 [  OK  ] Started getty@tty3.service - Getty on tty3.
62.779 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
62.799 [  OK  ] Started getty@tty4.service - Getty on tty4.
62.840 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
62.861 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
62.922 [  OK  ] Started getty@tty5.service - Getty on tty5.
62.922 [  OK  ] Started getty@tty6.service - Getty on tty6.
62.922 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
62.943 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
62.943 [  OK  ] Reached target getty.target - Login Prompts.
63.086 [  OK  ] Listening on systemd-rfkill.socketâ¦ll Switch Status /dev/rfkill Watch.
63.167 WRBOOT-NET eth0 mac=52:54:00:77:12:d6 10.77.0.86/24 fe80::5054:ff:fe77:12d6/64 
63.167 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
63.188 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
63.188 [  OK  ] Reached target multi-user.target - Multi-User System.
63.188 [  OK  ] Reached target graphical.target - Graphical Interface.
63.208          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
63.229 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
