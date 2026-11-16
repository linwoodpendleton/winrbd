# SPDX-License-Identifier: MIT
# Connect with python-rados, stat an object, run one monitor command, idle, repeat both.
# usage: pubidle.py <entity-id> <keyring> <mode: crc|secure|def> <seconds> <logfile>
import sys, time, rados
user, keyring, mode, secs, logf = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
conf = {'keyring': keyring, 'debug_ms': '5', 'debug_auth': '10',
        'log_file': logf, 'log_to_file': 'true', 'log_to_stderr': 'false'}
if mode != 'def':
    conf['ms_client_mode'] = mode
    conf['ms_mon_client_mode'] = mode
c = rados.Rados(name='client.' + user, conffile='/etc/ceph/ceph.conf', conf=conf)
c.connect()
io = c.open_ioctx('winrbd')
print('stat1', io.stat('rbd_directory'))
print('mon osd stat', c.mon_command('{"prefix":"osd stat"}', b'')[0])
time.sleep(secs)
print('stat2', io.stat('rbd_directory'))
print('mon osd stat 2', c.mon_command('{"prefix":"osd stat"}', b'')[0])
io.close(); c.shutdown()
