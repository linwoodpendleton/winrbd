#!/bin/bash
# SPDX-License-Identifier: MIT
# Regenerate the epoch-bound ground truth ("gt") at the current OSDMap epoch. Read-only on the cluster.
# Output: $ROOT/gt (default ROOT=$HOME/capture-work); names.py and osdmap_gt.py must sit next to this script. The oracle tools run inside the cluster's own container image (cephadm shell).
set -u
ROOT=${ROOT:-$HOME/capture-work}; G=$ROOT/gt; S=$(cd "$(dirname "$0")" && pwd)
rm -rf $G; mkdir -p $G; cd $S
A="sudo -n ceph"
E=$($A osd stat -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["epoch"])'); echo "epoch=$E" | tee $G/EPOCH.txt
$A osd getmap -o $G/osdmap.bin 2>&1 | tee -a $G/EPOCH.txt
$A osd getcrushmap -o $G/crush.bin 2>&1 | tee -a $G/EPOCH.txt
$A mon getmap -o $G/monmap.bin 2>&1 | tee -a $G/EPOCH.txt
E2=$($A osd stat -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["epoch"])'); echo "epoch_after=$E2" | tee -a $G/EPOCH.txt
$A osd dump -f json-pretty > $G/osd-dump.json
$A osd dump > $G/osd-dump.txt
$A osd tree -f json-pretty > $G/osd-tree.json
$A osd crush show-tunables -f json-pretty > $G/crush-tunables.json
$A osd crush rule dump -f json-pretty > $G/crush-rule-dump.json
$A osd crush dump -f json-pretty > $G/crush-dump.json
$A mon dump -f json-pretty > $G/mon-dump.json
$A osd stat -f json-pretty > $G/osd-stat.json
$A osd pool ls detail -f json-pretty > $G/pool-ls-detail.json
python3 $S/names.py > $G/names.json
sudo -n python3 $S/osdmap_gt.py $G/names.json $G/osd-map-all.jsonl
for n in rbd_data.37841afbd1d7.0000000000000000 rbd_data.37841afbd1d7.0000000000000001 rbd_header.37841afbd1d7 rbd_id.img-v1 rbd_directory foo abcdefghijkl abcdefghijklm; do
  echo "\$ ceph osd map winrbd $n"; $A osd map winrbd "$n"; done > $G/osd-map-text-winrbd.txt 2>&1
for n in foo rbd_directory; do echo "\$ ceph osd map winrbd $n (nspace ns)"; $A osd map winrbd $n ns; done >> $G/osd-map-text-winrbd.txt 2>&1
for n in foo a; do echo "\$ ceph osd map .mgr $n"; $A osd map .mgr $n; done > $G/osd-map-text-mgr.txt 2>&1
wc -l $G/osd-map-all.jsonl; grep -c '"rc": 0' $G/osd-map-all.jsonl
sudo chown -R $(id -un):$(id -gn) $G
