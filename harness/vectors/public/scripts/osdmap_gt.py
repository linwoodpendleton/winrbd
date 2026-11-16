# SPDX-License-Identifier: MIT
# Run 'osd map' (JSON) for every name through one admin mon session; writes JSON lines.
import json, rados, sys
names = json.load(open(sys.argv[1])); out = open(sys.argv[2], 'w')
c = rados.Rados(name='client.admin', conffile='/etc/ceph/ceph.conf', conf={'keyring': '/etc/ceph/ceph.client.admin.keyring'})
c.connect()
def q(pool, obj, ns=None):
    cmd = {'prefix': 'osd map', 'pool': pool, 'object': obj, 'format': 'json'}
    if ns is not None: cmd['nspace'] = ns
    rc, outb, outs = c.mon_command(json.dumps(cmd), b'')
    rec = {'pool': pool, 'object': obj, 'nspace': ns, 'rc': rc}
    if rc == 0: rec['result'] = json.loads(outb)
    else: rec['err'] = outs
    out.write(json.dumps(rec, ensure_ascii=True, sort_keys=True) + '\n')
for pool, key in (('winrbd', 'winrbd'), ('.mgr', 'mgr')):
    for n in names[key]: q(pool, n)
for n in names['winrbd'][:60]: q('winrbd', n, 'ns1')           # namespace variants
for n in names['winrbd'][:20]: q('winrbd', n, 'a-longer-namespace')
out.close(); c.shutdown()
