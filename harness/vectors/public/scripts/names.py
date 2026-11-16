# SPDX-License-Identifier: MIT
# Synthetic object-name generator for 'ceph osd map' ground truth. Deterministic (fixed seed).
import random, string, json, sys
r = random.Random(20261116)
def hexn(n): return ''.join(r.choice('0123456789abcdef') for _ in range(n))
img_ids = ['37841afbd1d7', '37863d7ada59'] + [hexn(12) for _ in range(6)] + [hexn(10) for _ in range(2)]
names = []
# rbd_data.<id>.<16 hex objno>: low numbers, boundaries, random 64-bit
for i in img_ids[:2]:
    for n in list(range(0, 300)) + [0x3ff, 0x400, 0xffff, 0x10000, 0xffffffff]:
        names.append('rbd_data.%s.%016x' % (i, n))
for i in img_ids[2:]:
    for n in list(range(0, 40)) + [r.getrandbits(32) for _ in range(40)] + [r.getrandbits(64) for _ in range(20)]:
        names.append('rbd_data.%s.%016x' % (i, n))
for i in img_ids:
    names += ['rbd_header.%s' % i, 'rbd_object_map.%s' % i, 'rbd_object_map.%s.%016x' % (i, 3)]
names += ['rbd_id.img-v1', 'rbd_id.img-default', 'rbd_id.myimage', 'rbd_directory', 'rbd_info', 'rbd_trash', 'rbd_children', 'rbd_mirroring', 'rbd_migration',
          'foo', 'bar', 'a', '', ]
names = [n for n in names if n]
# lengths around the rjenkins block size (12) and other edges
for L in (1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 23, 24, 25, 35, 36, 37, 64, 100, 200, 255):
    for _ in range(6):
        names.append(''.join(r.choice(string.ascii_letters + string.digits + '._-') for _ in range(L)))
# random strings, assorted lengths
while len(names) < 1900:
    L = r.randint(1, 80)
    names.append(''.join(r.choice(string.ascii_letters + string.digits + '._-:/ ') for _ in range(L)))
# non-ASCII (UTF-8), control-free
for s in ['café', '日本語-obj', 'ö-ü-ß', 'rbd_data.αβγ.0000000000000001', '\U0001F600smile', 'xÿĀy', 'kéy-with-longer-non-ascii-tail-1234567']:
    names.append(s)
names += ['name with space', 'trailing-space ', ' leading-space', 'a/b/c', '..', '.hidden', 'x' * 300]
seen = set(); out = []
for n in names:
    if n not in seen: seen.add(n); out.append(n)
json.dump({'winrbd': out[:2000],
           'mgr': [out[i] for i in range(0, len(out), max(1, len(out)//200))][:200]}, sys.stdout)
