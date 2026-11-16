session: k2-rbd-bench-v1
description: rbd create (layering only, 16 MiB), bench write 1 MiB then read 1 MiB (seq 64K), rm
user: client.vec-k2  key_type: aes256k
mode: crc (crc = --ms_client_mode crc --ms_mon_client_mode crc; sec = both secure; def = no mode options)
debug: ms=5 auth=10
netns client ip: 10.78.0.2; capture iface: t0v0 (host side of veth), filter 'host 10.78.0.2'
commands (common options added to each: -n client.vec-k2 --keyring <keyring> --debug_ms 5 --debug_auth 10 --log_file <per-command log> plus the mode options):
  [1] rbd create --size 16M --image-feature layering winrbd/t0-bench-k2
  [2] rbd bench --io-type write --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/t0-bench-k2
  [3] rbd bench --io-type read --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/t0-bench-k2
  [4] rbd rm winrbd/t0-bench-k2
