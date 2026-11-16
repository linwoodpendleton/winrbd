#!/bin/bash
# runs inside 'cephadm shell' (same image as the cluster): offline oracle tools, files under /t0/gt
# SPDX-License-Identifier: MIT
set -u
G=/t0/gt; cd $G
crushtool -d crush.bin -o crush.txt
crushtool -i crush.bin --dump > crush-dump.crushtool.json 2>&1
osdmaptool osdmap.bin --print > osdmaptool-print.txt 2>&1
osdmaptool osdmap.bin --dump json > osdmaptool-dump.json 2>&1
osdmaptool osdmap.bin --tree > osdmaptool-tree.txt 2>&1
for P in 1 2; do osdmaptool osdmap.bin --test-map-pgs-dump-all --pool $P > osdmaptool-test-map-pgs-dump-all.pool$P.txt 2>&1; done
osdmaptool osdmap.bin --test-map-pgs --pool 2 > osdmaptool-test-map-pgs.pool2.txt 2>&1
for o in foo rbd_directory rbd_header.37841afbd1d7 rbd_data.37841afbd1d7.0000000000000000 rbd_id.img-v1; do
  echo "\$ osdmaptool osdmap.bin --test-map-object $o --pool 2"; osdmaptool osdmap.bin --test-map-object $o --pool 2; done > osdmaptool-test-map-object.txt 2>&1
# crushtool placement tests (rules: see crush.txt). x = raw seed; with --pool-id the tool applies hash2(x,pool).
mkdir -p crushtool-tests
for R in 0 1; do
  for NR in 1 2 3; do
    crushtool -i crush.bin --test --show-mappings --rule $R --num-rep $NR --min-x 0 --max-x 9999 > crushtool-tests/rule$R.rep$NR.x0-9999.txt 2>&1
  done
done
crushtool -i crush.bin --test --show-mappings --rule 1 --num-rep 3 --min-x 0 --max-x 9999 --pool-id 2 > crushtool-tests/rule1.rep3.x0-9999.pool2.txt 2>&1
crushtool -i crush.bin --test --show-mappings --rule 0 --num-rep 2 --min-x 0 --max-x 9999 --pool-id 1 > crushtool-tests/rule0.rep2.x0-9999.pool1.txt 2>&1
crushtool -i crush.bin --test --show-statistics --show-utilization --rule 1 --num-rep 3 --min-x 0 --max-x 9999 > crushtool-tests/rule1.rep3.stats.txt 2>&1
# ceph-dencoder JSON dumps
ceph-dencoder type OSDMap import osdmap.bin decode dump_json > dencoder-OSDMap.json 2> dencoder-OSDMap.err
ceph-dencoder type MonMap import monmap.bin decode dump_json > dencoder-MonMap.json 2> dencoder-MonMap.err
ceph-dencoder type CrushWrapper import crush.bin decode dump_json > dencoder-CrushWrapper.json 2> dencoder-CrushWrapper.err
monmaptool --print monmap.bin > monmaptool-print.txt 2>&1
ceph-dencoder list_types > dencoder-types.txt 2>&1
chmod -R a+rX $G
ls -la $G | head -60
