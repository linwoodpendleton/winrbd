session: k2-sec-rbd-info
description: BOTH forced secure (ms_client_mode=secure ms_mon_client_mode=secure): rbd info img-v1, rados put/get/rm of a 100-byte object
user: client.vec-k2  key_type: aes256k
mode: sec (crc = --ms_client_mode crc --ms_mon_client_mode crc; sec = both secure; def = no mode options)
debug: ms=5 auth=30
netns client ip: 10.78.0.2; capture iface: t0v0 (host side of veth), filter 'host 10.78.0.2'
commands (common options added to each: -n client.vec-k2 --keyring <keyring> --debug_ms 5 --debug_auth 30 --log_file <per-command log> plus the mode options):
  [1] rbd info winrbd/img-v1
  [2] rados -p winrbd put t0-small <data>/small.bin
  [3] rados -p winrbd get t0-small <data>/small.k2.secget
  [4] rados -p winrbd rm t0-small
