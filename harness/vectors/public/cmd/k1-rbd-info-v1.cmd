session: k1-rbd-info-v1
description: rbd info of the layering-only image (cls calls, header reads)
user: client.vec-k1  key_type: aes
mode: crc (crc = --ms_client_mode crc --ms_mon_client_mode crc; sec = both secure; def = no mode options)
debug: ms=5 auth=10
netns client ip: 10.78.0.2; capture iface: t0v0 (host side of veth), filter 'host 10.78.0.2'
commands (common options added to each: -n client.vec-k1 --keyring <keyring> --debug_ms 5 --debug_auth 10 --log_file <per-command log> plus the mode options):
  [1] rbd info winrbd/img-v1
