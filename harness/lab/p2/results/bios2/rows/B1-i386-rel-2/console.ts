# tailts start epoch=1795481700.404
8.158 iPXE initialising devices...
8.179 
8.201 
8.222 
8.244 iPXE 2.0.0+ -- Open Source Network Boot Firmware -- https://ipxe.org
8.265 Features: DNS HTTP iSCSI TFTP AoE ELF MBOOT PXE bzImage Menu PXEXT
8.285 WRRUN-STUB
11.329 Configuring (net0 52:54:00:77:12:c7)...... ok
11.370 tftp://10.77.0.10/autoexec.ipxe... ok
11.390 WRRUN-BEGIN row=B1
11.452 Waiting for link-up on net0... ok
11.452 WRRUN-NET-OK
11.473 WRRUN-SAN-START sanboot
11.764 Registered SAN device 0x80
11.786 Booting from SAN device 0x80
14.473 GNU GRUB  version 2.14
14.473 
14.494 +----------------------------------------------------------------------------+||||||||||||||||||||||||+----------------------------------------------------------------------------+     Use the ^ and v keys to select which entry is highlighted.          
14.494       Press enter to boot the selected OS, `e' to edit the commands       
25.142       before booting or `c' for a command-line.                            *winrbd Linux: check the table, root from the image if there is one          winrbd Linux: local root only (no hook)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                The highlighted entry will be executed automatically in 2s.                    The highlighted entry will be executed automatically in 1s.                    The highlighted entry will be executed automatically in 0s.                 Loading, please wait...
25.162 Starting systemd-udevd version 255.4-1ubuntu8.19
25.806 Begin: Loading essential drivers ... done.
25.828 Begin: Running /scripts/init-premount ... done.
25.849 Begin: Mounting root file system ... Begin: Running /scripts/local-top ... 
25.849 RBFT-HOOK start: map=1 src=auto rootpart=1 require=1
26.181 RBFT-HOOK table found by source scan
26.181 RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:c7
26.202 RBFT-HOOK nic: eth0 address 10.77.0.71/24
26.202 RBFT-HOOK table check (source scan):
26.475 RBFT INFO source: scan: found at physical address 0x9a880 (1 valid copy/copies)
26.475 RBFT PASS signature: rBFT
26.475 RBFT PASS length: 234 bytes
26.475 RBFT PASS acpi_revision: 1
26.475 RBFT PASS checksum: all 234 bytes sum to 0
26.475 RBFT INFO oem: not interpreted (iPXE writes its own): id 'FENSYS' table id 'iPXE' creator ''
26.496 RBFT PASS magic: WRBT
26.496 RBFT PASS version: 1
26.496 RBFT PASS header_len: 116
26.496 RBFT PASS reserved: all reserved bytes are zero
26.496 RBFT PASS flags_reserved: only bits 0..5 are set (0x6)
26.496 RBFT PASS layout: canonical: strings, 1 monitor records, key, nothing else (82 bytes of area)
26.496 RBFT PASS namespace: absent (as in version 1)
26.496 RBFT PASS rules: every rule of the field table holds
26.496 RBFT PASS entity: wrtest-p2-b1
26.496 RBFT PASS pool: winrbd
26.496 RBFT PASS image: wrtest-p2-b1
26.496 RBFT PASS image_id: 3fae3418fe30
26.496 RBFT PASS snapshot: absent, as expected
26.496 RBFT PASS auth: cephx
26.496 RBFT PASS msgr_mode: crc
26.496 RBFT PASS flags: key,static (0x6)
26.496 RBFT PASS flag_readonly: clear
26.517 RBFT PASS flag_key: set
26.517 RBFT PASS flag_nic_static: set
26.517 RBFT PASS flag_vlan: clear
26.517 RBFT PASS flag_fsid: clear
26.517 RBFT PASS flag_secure_required: clear
26.517 RBFT PASS key_type: aes
26.517 RBFT PASS key_len: 16
26.517 RBFT INFO key: present in the table (aes, 16 bytes), not printed
26.517 RBFT PASS mon_count: 1
26.517 RBFT PASS mon0: 10.77.0.10:3300
26.517 RBFT PASS fsid: none, as expected
26.517 RBFT PASS nic_mac: 52:54:00:77:12:c7
26.517 RBFT PASS nic_present: an interface with MAC 52:54:00:77:12:c7 exists in this guest
26.517 RBFT PASS nic_vlan: 0
26.517 RBFT PASS nic_mtu: 1500
26.517 RBFT PASS nic_family: 4
26.517 RBFT PASS nic_ip: 10.77.0.71
26.517 RBFT PASS nic_prefix: 24
26.539 RBFT PASS nic_gateway: zero, as expected
26.539 RBFT PASS nic_dns: zero, as expected
26.539 RBFT DUMP 0000: 72 42 46 54 ea 00 00 00 01 ee 46 45 4e 53 59 53
26.539 RBFT DUMP 0010: 69 50 58 45 00 00 00 00 00 00 00 00 00 00 00 00
26.539 RBFT DUMP 0020: 00 00 00 00 57 52 42 54 01 00 74 00 06 00 00 00
26.539 RBFT DUMP 0030: 01 01 01 10 01 04 18 00 00 00 00 00 00 00 00 00
26.539 RBFT DUMP 0040: 00 00 00 00 00 00 00 00 52 54 00 77 12 c7 00 00
26.539 RBFT DUMP 0050: dc 05 00 00 0a 4d 00 47 00 00 00 00 00 00 00 00
26.539 RBFT DUMP 0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.539 RBFT DUMP 0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
26.539 RBFT DUMP 0080: 00 00 00 00 00 00 0d 00 ff ff 14 00 21 00 ff ff
26.560 RBFT DUMP 0090: 2e 00 42 00 00 00 00 00 77 72 74 65 73 74 2d 70
26.560 RBFT DUMP 00a0: 32 2d 62 31 00 77 69 6e 72 62 64 00 77 72 74 65
26.560 RBFT DUMP 00b0: 73 74 2d 70 32 2d 62 31 00 33 66 61 65 33 34 31
26.560 RBFT DUMP 00c0: 38 66 65 33 30 00 04 00 e4 0c 0a 4d 00 0a 00 00
26.560 RBFT DUMP 00d0: 00 00 00 00 00 00 00 00 00 00 .. .. .. .. .. ..
26.560 RBFT DUMP 00e0: .. .. .. .. .. .. .. .. .. ..
26.560 RBFT-RESULT PASS pass=40 fail=0 skip=0
26.560 WRBOOT-TABLE PASS
26.624 RBFT-HOOK map: pool winrbd image wrtest-p2-b1 via 10.77.0.10:3300 as client.wrtest-p2-b1 (options ms_mode=crc,noshare, the key is not shown)
26.729 RBFT-HOOK map: image winrbd/wrtest-p2-b1 is /dev/rbd0, root device /dev/rbd0p1
26.729 WRBOOT-HOOK-DONE root=/dev/rbd0p1 table=PASS
26.729 done.
26.750 Begin: Running /scripts/local-premount ... done.
56.864 Warning: fsck not present, so skipping root file system
56.906 done.
56.927 Begin: Running /scripts/local-bottom ... done.
56.970 Begin: Running /scripts/init-bottom ... done.
58.437 
58.437 Welcome to Ubuntu 24.04 LTS!
58.437 
59.990 [  OK  ] Created slice system-getty.slice - Slice /system/getty.
59.990 [  OK  ] Created slice system-modprobe.slice - Slice /system/modprobe.
59.990 [  OK  ] Created slice system-serial\x2dgetâ¦slice - Slice /system/serial-getty.
59.990 [  OK  ] Created slice user.slice - User and Session Slice.
60.012 [  OK  ] Started systemd-ask-password-consoâ¦equests to Console Directory Watch.
60.012 [  OK  ] Started systemd-ask-password-wall.â¦d Requests to Wall Directory Watch.
60.012 [  OK  ] Set up automount proc-sys-fs-binfmâ¦ormats File System Automount Point.
60.012          Expecting device dev-ttyS0.device - /dev/ttyS0...
60.012 [  OK  ] Reached target cryptsetup.target - Local Encrypted Volumes.
60.033 [  OK  ] Reached target integritysetup.targâ¦ Local Integrity Protected Volumes.
60.033 [  OK  ] Reached target paths.target - Path Units.
60.033 [  OK  ] Reached target remote-fs.target - Remote File Systems.
60.033 [  OK  ] Reached target slices.target - Slice Units.
60.033 [  OK  ] Reached target swap.target - Swaps.
60.033 [  OK  ] Reached target veritysetup.target - Local Verity Protected Volumes.
60.055 [  OK  ] Listening on systemd-initctl.sockeâ¦- initctl Compatibility Named Pipe.
60.055 [  OK  ] Listening on systemd-journald-dev-â¦socket - Journal Socket (/dev/log).
60.055 [  OK  ] Listening on systemd-journald.socket - Journal Socket.
60.055 [  OK  ] Listening on systemd-udevd-control.socket - udev Control Socket.
60.055 [  OK  ] Listening on systemd-udevd-kernel.socket - udev Kernel Socket.
60.077          Mounting dev-hugepages.mount - Huge Pages File System...
60.121          Mounting dev-mqueue.mount - POSIX Message Queue File System...
60.121          Mounting sys-kernel-debug.mount - Kernel Debug File System...
60.143          Mounting sys-kernel-tracing.mount - Kernel Trace File System...
60.186          Starting systemd-journald.service - Journal Service...
60.186          Starting kmod-static-nodes.serviceâ¦eate List of Static Device Nodes...
60.207          Starting modprobe@configfs.service - Load Kernel Module configfs...
60.250          Starting modprobe@dm_mod.service - Load Kernel Module dm_mod...
60.293          Starting modprobe@drm.service - Load Kernel Module drm...
60.314          Starting modprobe@efi_pstore.serviâ¦ - Load Kernel Module efi_pstore...
60.314          Starting modprobe@fuse.service - Load Kernel Module fuse...
60.357          Starting modprobe@loop.service - Load Kernel Module loop...
60.378          Starting systemd-modules-load.service - Load Kernel Modules...
60.378          Starting systemd-remount-fs.servicâ¦unt Root and Kernel File Systems...
60.400          Starting systemd-udev-trigger.service - Coldplug All udev Devices...
60.421 [  OK  ] Started systemd-journald.service - Journal Service.
60.421 [  OK  ] Mounted dev-hugepages.mount - Huge Pages File System.
60.443 [  OK  ] Mounted dev-mqueue.mount - POSIX Message Queue File System.
60.443 [  OK  ] Mounted sys-kernel-debug.mount - Kernel Debug File System.
60.465 [  OK  ] Mounted sys-kernel-tracing.mount - Kernel Trace File System.
60.465 [  OK  ] Finished kmod-static-nodes.serviceâ¦Create List of Static Device Nodes.
60.486 [  OK  ] Finished modprobe@configfs.service - Load Kernel Module configfs.
60.486 [  OK  ] Finished modprobe@dm_mod.service - Load Kernel Module dm_mod.
60.511 [  OK  ] Finished modprobe@drm.service - Load Kernel Module drm.
60.554 [  OK  ] Finished modprobe@efi_pstore.service - Load Kernel Module efi_pstore.
60.575 [  OK  ] Finished modprobe@fuse.service - Load Kernel Module fuse.
60.597 [  OK  ] Finished modprobe@loop.service - Load Kernel Module loop.
60.597 [  OK  ] Finished systemd-modules-load.service - Load Kernel Modules.
60.642 [  OK  ] Finished systemd-remount-fs.servicâ¦mount Root and Kernel File Systems.
60.663          Mounting sys-fs-fuse-connections.mount - FUSE Control File System...
60.685          Mounting sys-kernel-config.mount - Kernel Configuration File System...
60.706          Starting systemd-random-seed.service - Load/Save OS Random Seed...
60.727          Starting systemd-sysctl.service - Apply Kernel Variables...
60.770          Starting systemd-tmpfiles-setup-deâ¦ Device Nodes in /dev gracefully...
60.792 [  OK  ] Mounted sys-fs-fuse-connections.mount - FUSE Control File System.
60.792 [  OK  ] Mounted sys-kernel-config.mount - Kernel Configuration File System.
60.813 [  OK  ] Finished systemd-random-seed.service - Load/Save OS Random Seed.
60.877 [  OK  ] Finished systemd-sysctl.service - Apply Kernel Variables.
60.941 [  OK  ] Finished systemd-udev-trigger.service - Coldplug All udev Devices.
61.004 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦ic Device Nodes in /dev gracefully.
61.026          Starting systemd-tmpfiles-setup-deâ¦eate Static Device Nodes in /dev...
61.089 [  OK  ] Finished systemd-tmpfiles-setup-deâ¦Create Static Device Nodes in /dev.
61.089 [  OK  ] Reached target local-fs-pre.targetâ¦Preparation for Local File Systems.
61.110          Mounting tmp.mount - /tmp...
61.132          Mounting var-cache.mount - /var/cache...
61.153          Mounting var-log.mount - /var/log...
61.175          Mounting var-tmp.mount - /var/tmp...
61.196          Starting systemd-udevd.service - Râ¦ager for Device Events and Files...
61.217 [  OK  ] Mounted tmp.mount - /tmp.
61.217 [  OK  ] Mounted var-cache.mount - /var/cache.
61.217 [  OK  ] Mounted var-log.mount - /var/log.
61.239 [  OK  ] Mounted var-tmp.mount - /var/tmp.
61.239 [  OK  ] Reached target local-fs.target - Local File Systems.
61.260 [  OK  ] Listening on systemd-sysext.socketâ¦tension Image Management (Varlink).
61.282 [  OK  ] Reached target sockets.target - Socket Units.
61.303          Starting systemd-journal-flush.serâ¦sh Journal to Persistent Storage...
61.346 [  OK  ] Finished systemd-journal-flush.serâ¦lush Journal to Persistent Storage.
61.389          Starting systemd-tmpfiles-setup.seâ¦e Volatile Files and Directories...
61.495 [  OK  ] Finished systemd-tmpfiles-setup.seâ¦ate Volatile Files and Directories.
61.516          Starting systemd-update-utmp.serviâ¦ord System Boot/Shutdown in UTMP...
61.580 [  OK  ] Finished systemd-update-utmp.serviâ¦ecord System Boot/Shutdown in UTMP.
61.729 [  OK  ] Started systemd-udevd.service - Ruâ¦anager for Device Events and Files.
61.729 [  OK  ] Reached target sysinit.target - System Initialization.
61.729 [  OK  ] Started apt-daily.timer - Daily apt download activities.
61.751 [  OK  ] Started apt-daily-upgrade.timer - â¦y apt upgrade and clean activities.
61.751 [  OK  ] Started dpkg-db-backup.timer - Daily dpkg database backup timer.
61.772 [  OK  ] Started e2scrub_all.timer - Periodâ¦Metadata Check for All Filesystems.
61.772 [  OK  ] Started fstrim.timer - Discard unused filesystem blocks once a week.
61.772 [  OK  ] Started motd-news.timer - Message of the Day.
61.793 [  OK  ] Started systemd-tmpfiles-clean.timâ¦y Cleanup of Temporary Directories.
61.793 [  OK  ] Reached target timers.target - Timer Units.
61.793 [  OK  ] Reached target basic.target - Basic System.
61.815          Starting e2scrub_reap.service - Reâ¦ne ext4 Metadata Check Snapshots...
61.836          Starting getty-static.service - geâ¦bus and logind are not available...
61.880          Starting systemd-user-sessions.service - Permit User Sessions...
61.966          Starting wrboot-marker.service - Pâ¦inrbd boot marker on the console...
61.966 [  OK  ] Finished systemd-user-sessions.service - Permit User Sessions.
62.051 [  OK  ] Started getty@tty1.service - Getty on tty1.
62.157 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0002
62.157 [  OK  ] Finished e2scrub_reap.service - Reâ¦line ext4 Metadata Check Snapshots.
62.283 [  OK  ] Found device dev-ttyS0.device - /dev/ttyS0.
62.346 [  OK  ] Started getty@tty2.service - Getty on tty2.
62.397 [  OK  ] Started getty@tty3.service - Getty on tty3.
62.397 WRBOOT-NET eth0 mac=52:54:00:77:12:c7 10.77.0.71/24 fe80::5054:ff:fe77:12c7/64 
62.397 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
62.418 [  OK  ] Started getty@tty4.service - Getty on tty4.
62.440 [  OK  ] Started getty@tty5.service - Getty on tty5.
62.461 [  OK  ] Started getty@tty6.service - Getty on tty6.
62.483 [  OK  ] Started serial-getty@ttyS0.service - Serial Getty on ttyS0.
62.504 [  OK  ] Finished getty-static.service - geâ¦ dbus and logind are not available.
62.504 [  OK  ] Finished wrboot-marker.service - Pâ¦ winrbd boot marker on the console.
62.525 [  OK  ] Reached target getty.target - Login Prompts.
62.525 [  OK  ] Reached target multi-user.target - Multi-User System.
62.525 [  OK  ] Reached target graphical.target - Graphical Interface.
62.547          Starting systemd-update-utmp-runleâ¦- Record Runlevel Change in UTMP...
62.610 [  OK  ] Finished systemd-update-utmp-runleâ¦e - Record Runlevel Change in UTMP.
