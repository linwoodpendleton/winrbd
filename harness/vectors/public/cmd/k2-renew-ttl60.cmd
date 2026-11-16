session: k2-renew-ttl60
description: auth_service_ticket_ttl=60 on the mon: python rados client, op, 150 s idle, op (ticket renewal / re-auth)
user: client.vec-k2  key_type: aes256k
mode: crc (crc = --ms_client_mode crc --ms_mon_client_mode crc; sec = both secure; def = no mode options)
debug: ms=5 auth=10
netns client ip: 10.78.0.2; capture iface: t0v0 (host side of veth), filter 'host 10.78.0.2'
commands (common options added to each: -n client.vec-k2 --keyring <keyring> --debug_ms 5 --debug_auth 10 --log_file <per-command log> plus the mode options):
  [1] python3 pubidle.py vec-k2 <keyring> crc 150
