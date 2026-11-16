session: k2-rados-big
description: rados put/stat/get/rm of a 1 MiB + 1234 byte object
user: client.vec-k2  key_type: aes256k
mode: crc (crc = --ms_client_mode crc --ms_mon_client_mode crc; sec = both secure; def = no mode options)
debug: ms=5 auth=10
netns client ip: 10.78.0.2; capture iface: t0v0 (host side of veth), filter 'host 10.78.0.2'
commands (common options added to each: -n client.vec-k2 --keyring <keyring> --debug_ms 5 --debug_auth 10 --log_file <per-command log> plus the mode options):
  [1] rados -p winrbd put t0-big <data>/big.bin
  [2] rados -p winrbd stat t0-big
  [3] rados -p winrbd get t0-big <data>/big.k2.get
  [4] rados -p winrbd rm t0-big
