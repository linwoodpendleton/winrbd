#!/bin/bash
# SPDX-License-Identifier: MIT
#
# capture_osdc.sh - the lab captures of module vectors-c (harness/vectors/public/osdc/): the OSD requests and replies of the stock
# client library for the header reads of RBD images (every feature word of the refusal table), the object operations of the data
# path, writes with a snapshot context, PG backoffs, and the data objects of patterned images.
#
# Runs INSIDE the disposable lab VM, as a user with passwordless sudo, with the stock tools (ceph, rbd, rados, tcpdump) and g++ with
# librados headers. Everything it creates is named wrtest-osdc-* or client.vec-osdc and is removed again; the state it changes
# (a throwaway cephx user, the options osd_backoff_on_peering, osd_backoff_on_degraded and mon_allow_pool_delete, one OSD restart, one
# `osd out` and `osd in`) is put back and the
# result is proven in revert-proof.txt. Usage:
#
#     capture_osdc.sh run [OUTDIR]          the whole thing; the vector tree is written to OUTDIR (default $WORK/osdc)
#     capture_osdc.sh help
#
# Environment: WORK (default $HOME/w/vectors-c/cap)  POOL (default winrbd)  SCRIPTS (default: the directory of this file, where
# check_osdc.py is). The C++ client driver (osdc_probe, librados) is embedded below.
#
# The cephx user is created with default key type, used in crc mode only, and deleted at the end (`ceph auth get` must fail, which the
# script verifies before it writes the vectors). Its key is not part of the published set: crc-mode messages carry no secret, so the
# vectors never needed it; the script scans the finished tree for the key text and aborts on a hit. The cluster's admin key is used
# only for the setup and the clean-up commands (rbd, rados, ceph), never from inside the capture namespace.
set -u

WORK=${WORK:-$HOME/w/vectors-c/cap}
POOL=${POOL:-winrbd}
DPOOL=wrtest-osdc-data
USERN=vec-osdc
SCRIPTS=${SCRIPTS:-$(cd "$(dirname "$0")" && pwd)}
NSNAME=vocns
VETH_H=voc0
VETH_C=voc1
NET_H=${NET_H:-192.0.2.1}   # the namespace's own point-to-point net: documentation addresses (the lab's 10.77.0.x is reached through the host)
NET_C=${NET_C:-192.0.2.2}
NS="sudo -n ip netns exec $NSNAME"
A="sudo -n ceph"
R="sudo -n rbd"
RD="sudo -n rados -p $POOL"
KEYRING=$WORK/keys/client.$USERN.keyring
IMGS="f01 f05 f21 f3d f45 dp clone str snap lock"
PATS="pat12 pat14 pat16"
CONFIG_TOUCHED=""

die() { echo "capture_osdc: $*" >&2; exit 1; }
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
epoch() { $A osd stat -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["epoch"])'; }
iname() { echo "wrtest-osdc-$1"; }

# ---- the C++ client driver (osdc_probe) -------------------------------------------------------------------------------

build_probe() {
  write_probe_src > "$WORK/osdc_probe.cc"
  g++ -std=c++17 -O0 -Wall -pthread -o "$WORK/osdc_probe" "$WORK/osdc_probe.cc" -lrados || die "the probe does not compile (librados development files?)"
}

write_probe_src() {
cat <<'CPP_END'
// SPDX-License-Identifier: MIT
// osdc_probe: lab-only driver that sends the OSD requests the stock tools never send (compound class calls, writes with a
// snapshot context, a spread of object operations) with librados, in crc mode, and prints what the API reported, one JSON
// object per line. The wire is the evidence; this is the label list. Not part of any build of the project.
#include <rados/librados.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <unistd.h>
#include <mutex>
#include <thread>

using namespace librados;
using ceph::bufferlist;

static IoCtx io;
static Rados cluster;

static std::string hex(const char *p, size_t n)
{
	static const char *d = "0123456789abcdef";
	std::string s;
	for (size_t i = 0; i < n; i++) {
		s += d[((unsigned char)p[i]) >> 4];
		s += d[((unsigned char)p[i]) & 15];
	}
	return s;
}
static std::string hexbl(const bufferlist &b)
{
	bufferlist c = b;
	return hex(c.c_str(), c.length());
}
static std::string u64le(uint64_t v)
{
	std::string s;
	for (int i = 0; i < 8; i++)
		s += (char)((v >> (8 * i)) & 255);
	return s;
}
static std::string lestr(const std::string &x)
{
	std::string s;
	uint32_t n = (uint32_t)x.size();
	for (int i = 0; i < 4; i++)
		s += (char)((n >> (8 * i)) & 255);
	return s + x;
}
static const uint64_t NOSNAP = 0xfffffffffffffffeull;

static bufferlist bl_of(const std::string &s)
{
	bufferlist b;
	b.append(s.data(), s.size());
	return b;
}

// pattern of the lab: byte i = (i * mul + add) mod 251
static std::string pat(size_t n, int mul, int add, size_t start = 0)
{
	std::string s(n, 0);
	for (size_t i = 0; i < n; i++)
		s[i] = (char)(((start + i) * mul + add) % 251);
	return s;
}

static int step_no = 0;
static void jl_begin(const char *label, const std::string &oid)
{
	printf("{\"n\":%d,\"label\":\"%s\",\"oid\":\"%s\"", ++step_no, label, oid.c_str());
}
static void jl_end(int rc)
{
	printf(",\"rc\":%d}\n", rc);
	fflush(stdout);
}

struct Call {
	std::string cls, method, in;
	bufferlist out;
	int rval = -12345;
};

// one read message made of class calls
static int calls(const char *label, const std::string &oid, std::vector<Call> &cs)
{
	ObjectReadOperation r;
	std::vector<bufferlist> ins(cs.size());
	for (size_t i = 0; i < cs.size(); i++) {
		ins[i] = bl_of(cs[i].in);
		r.exec(cs[i].cls.c_str(), cs[i].method.c_str(), ins[i], &cs[i].out, &cs[i].rval);
	}
	bufferlist all;
	int rc = io.operate(oid, &r, &all);
	jl_begin(label, oid);
	printf(",\"kind\":\"calls\",\"calls\":[");
	for (size_t i = 0; i < cs.size(); i++)
		printf("%s{\"cls\":\"%s\",\"method\":\"%s\",\"in\":\"%s\",\"out\":\"%s\",\"rval\":%d}", i ? "," : "", cs[i].cls.c_str(),
		       cs[i].method.c_str(), hex(cs[i].in.data(), cs[i].in.size()).c_str(), hexbl(cs[i].out).c_str(), cs[i].rval);
	printf("]");
	jl_end(rc);
	return rc;
}

static std::string lock_get_info_in()
{
	// struct v1/compat 1 + string name
	std::string name = "rbd_lock", body = lestr(name);
	std::string s;
	s += (char)1;
	s += (char)1;
	uint32_t n = (uint32_t)body.size();
	for (int i = 0; i < 4; i++)
		s += (char)((n >> (8 * i)) & 255);
	return s + body;
}

static void hdr_session(const std::string &name, const std::string &id, uint64_t features)
{
	std::string hdr = "rbd_header." + id;
	{
		std::vector<Call> c(1);
		c[0] = {"rbd", "get_id", "", {}, -12345};
		calls("get_id", "rbd_id." + name, c);
	}
	for (int ro = 1; ro >= 0; ro--) {
		std::vector<Call> c = {{"rbd", "get_size", u64le(NOSNAP), {}, -12345},
				       {"rbd", "get_object_prefix", "", {}, -12345},
				       {"rbd", "get_features", u64le(NOSNAP) + std::string(1, (char)ro), {}, -12345},
				       {"rbd", "get_flags", u64le(NOSNAP), {}, -12345},
				       {"rbd", "get_snapcontext", "", {}, -12345},
				       {"rbd", "get_data_pool", "", {}, -12345},
				       {"rbd", "parent_get", "", {}, -12345},
				       {"rbd", "parent_overlap_get", u64le(NOSNAP), {}, -12345}};
		calls(ro ? "header8-reader" : "header8-writer", hdr, c);
	}
	if (features & 2) {
		std::vector<Call> c = {{"rbd", "get_stripe_unit_count", "", {}, -12345}};
		calls("stripe-unit-count", hdr, c);
	}
	if (features & 0x100) {
		std::vector<Call> c = {{"rbd", "op_features_get", "", {}, -12345}};
		calls("op-features", hdr, c);
	}
	{
		std::vector<Call> c = {{"lock", "get_info", lock_get_info_in(), {}, -12345}};
		calls("lock-get-info", hdr, c);
	}
}

static void hdr_missing()
{
	{
		std::vector<Call> c = {{"rbd", "get_id", "", {}, -12345}};
		calls("get_id-missing", "rbd_id.wrtest-osdc-none", c);
	}
	std::vector<Call> c = {{"rbd", "get_size", u64le(NOSNAP), {}, -12345},
			       {"rbd", "get_object_prefix", "", {}, -12345},
			       {"rbd", "get_features", u64le(NOSNAP) + std::string(1, (char)1), {}, -12345},
			       {"rbd", "get_flags", u64le(NOSNAP), {}, -12345},
			       {"rbd", "get_snapcontext", "", {}, -12345},
			       {"rbd", "get_data_pool", "", {}, -12345},
			       {"rbd", "parent_get", "", {}, -12345},
			       {"rbd", "parent_overlap_get", u64le(NOSNAP), {}, -12345}};
	calls("header8-missing", "rbd_header.0123456789ab", c);
}

// ---- data path ------------------------------------------------------------------------------------------------

static int do_read(const char *label, const std::string &oid, uint64_t off, uint64_t len, int sparse = 0, int stat = 0)
{
	ObjectReadOperation r;
	bufferlist out;
	int rv = -12345;
	std::map<uint64_t, uint64_t> ext;
	uint64_t size = 0;
	time_t mt = 0;
	if (stat)
		r.stat(&size, &mt, &rv);
	else if (sparse)
		r.sparse_read(off, len, &ext, &out, &rv);
	else
		r.read(off, len, &out, &rv);
	bufferlist all;
	int rc = io.operate(oid, &r, &all);
	jl_begin(label, oid);
	printf(",\"kind\":\"%s\",\"off\":%llu,\"len\":%llu,\"rval\":%d", stat ? "stat" : sparse ? "sparse" : "read", (unsigned long long)off,
	       (unsigned long long)len, rv);
	if (stat)
		printf(",\"size\":%llu,\"mtime\":%lld", (unsigned long long)size, (long long)mt);
	else
		printf(",\"data_len\":%u,\"data\":\"%s\"", (unsigned)out.length(), hexbl(out).c_str());
	if (sparse) {
		printf(",\"extents\":[");
		int f = 1;
		for (auto &e : ext) {
			printf("%s[%llu,%llu]", f ? "" : ",", (unsigned long long)e.first, (unsigned long long)e.second);
			f = 0;
		}
		printf("]");
	}
	jl_end(rc);
	return rc;
}

static int do_write_op(const char *label, const std::string &oid, ObjectWriteOperation &w, const char *what)
{
	int rc = io.operate(oid, &w);
	jl_begin(label, oid);
	printf(",\"kind\":\"write\",\"what\":\"%s\"", what);
	jl_end(rc);
	return rc;
}

static int w_write(const char *label, const std::string &oid, uint64_t off, const std::string &d)
{
	ObjectWriteOperation w;
	w.write(off, bl_of(d));
	char what[64];
	snprintf(what, sizeof what, "write %llu+%zu", (unsigned long long)off, d.size());
	return do_write_op(label, oid, w, what);
}
static int w_zero(const char *label, const std::string &oid, uint64_t off, uint64_t len)
{
	ObjectWriteOperation w;
	w.zero(off, len);
	char what[64];
	snprintf(what, sizeof what, "zero %llu+%llu", (unsigned long long)off, (unsigned long long)len);
	return do_write_op(label, oid, w, what);
}
static int w_trunc(const char *label, const std::string &oid, uint64_t off)
{
	ObjectWriteOperation w;
	w.truncate(off);
	char what[64];
	snprintf(what, sizeof what, "truncate %llu", (unsigned long long)off);
	return do_write_op(label, oid, w, what);
}
static int w_remove(const char *label, const std::string &oid)
{
	ObjectWriteOperation w;
	w.remove();
	return do_write_op(label, oid, w, "remove");
}

// the object operations of the data path on a few objects of an image: oid = <prefix>.<16 hex>
static std::string objname(const std::string &prefix, uint64_t n)
{
	char b[24];
	snprintf(b, sizeof b, ".%016llx", (unsigned long long)n);
	return prefix + b;
}

static void io_session(const std::string &prefix, uint64_t objsize)
{
	std::string o0 = objname(prefix, 0), o1 = objname(prefix, 1), o2 = objname(prefix, 2), o3 = objname(prefix, 3);
	do_read("read-missing", o0, 0, objsize);
	do_read("stat-missing", o0, 0, 0, 0, 1);
	w_write("write-4k", o0, 0, pat(4096, 7, 3));
	do_read("read-short", o0, 0, objsize);          // object is shorter than the extent
	do_read("read-exact", o0, 0, 4096);
	do_read("read-past-end", o0, 8192, 4096);        // starts beyond the object
	do_read("read-whole-len0", o0, 0, 0);            // length 0 = whole object
	w_write("write-hole", o0, 10000, pat(100, 13, 5)); // leaves a hole 4096..10000
	do_read("read-hole", o0, 0, objsize);
	do_read("sparse-hole", o0, 0, objsize, 1);       // two extents
	do_read("stat", o0, 0, 0, 0, 1);
	w_zero("zero-middle", o0, 100, 200);              // stays ZERO
	do_read("read-after-zero", o0, 0, 4096);
	do_read("sparse-after-zero", o0, 0, objsize, 1);
	w_zero("zero-to-end", o0, 5000, objsize - 5000);  // the OSD rewrites it as TRUNCATE
	do_read("stat-after-zero-to-end", o0, 0, 0, 0, 1);
	w_trunc("truncate-shrink", o0, 2000);
	w_trunc("truncate-extend", o0, 12000);
	do_read("read-after-extend", o0, 0, objsize);
	w_write("write-full-object", o1, 0, pat(objsize, 11, 7));
	do_read("read-full-object", o1, 0, objsize);
	do_read("read-mid-object", o1, objsize / 2, 1000);
	w_zero("zero-whole-object", o1, 0, objsize);    // becomes TRUNCATE(0)
	do_read("stat-after-zero-whole", o1, 0, 0, 0, 1);
	w_remove("delete", o0);
	w_remove("delete-again", o0);                    // -ENOENT
	do_read("read-after-delete", o0, 0, objsize);
	w_zero("zero-absent", o2, 0, 100);               // no-op, success
	w_trunc("truncate-absent", o2, 100);
	do_read("stat-after-noops", o2, 0, 0, 0, 1);
	{
		// as librbd writes: allocation hint (FAILOK) then WRITE
		ObjectWriteOperation w;
		w.set_alloc_hint2(objsize, 4096, 0);
		w.write(4096, bl_of(pat(512, 3, 1)));
		do_write_op("hint-and-write", o3, w, "set_alloc_hint + write 4096+512");
	}
	do_read("read-hint-object", o3, 0, objsize);
	w_remove("delete-o3", o3);
	w_remove("delete-o1", o1);
}

// writes with a snapshot context on an image that has snapshots; reads of a snapshot
static void snap_session(const std::string &prefix, uint64_t objsize, uint64_t seq, const std::vector<uint64_t> &snaps)
{
	std::string o0 = objname(prefix, 0), o1 = objname(prefix, 1), o2 = objname(prefix, 2);
	std::vector<snap_t> sv(snaps.begin(), snaps.end());
	do_read("read-head-before", o0, 0, objsize);
	if (io.selfmanaged_snap_set_write_ctx(seq, sv) != 0)
		fprintf(stderr, "snap_set_write_ctx failed\n");
	w_write("write-with-snapc", o0, 0, pat(2048, 5, 9));
	do_read("read-head-after", o0, 0, objsize);
	io.snap_set_read(snaps.back());
	do_read("read-oldest-snap", o0, 0, objsize);
	do_read("read-oldest-snap-missing", objname(prefix, 9), 0, objsize);
	io.snap_set_read(snaps.front());
	do_read("read-newest-snap", o0, 0, objsize);
	io.snap_set_read(LIBRADOS_SNAP_HEAD);
	w_write("write-new-object-snapc", o2, 0, pat(1024, 9, 2));
	w_zero("zero-with-snapc", o1, 100, 300);
	w_trunc("truncate-with-snapc", o1, objsize / 2);
	w_remove("delete-with-snapc", o1);              // leaves a whiteout while snapshots exist
	do_read("read-after-whiteout", o1, 0, objsize);   // the head is only a whiteout: -ENOENT
	io.snap_set_read(snaps.back());
	do_read("read-snap-after-delete", o1, 0, objsize);
	io.snap_set_read(LIBRADOS_SNAP_HEAD);
	// an empty context: the head is written without a clone being made
	std::vector<snap_t> none;
	io.selfmanaged_snap_set_write_ctx(0, none);
	w_write("write-empty-snapc", o2, 2048, pat(512, 17, 4));
}

// a steady load: sync writes and reads over many objects (many PGs) for `secs` seconds, from `nthreads` threads sharing one connection
static std::mutex out_mu;
static void loop_thread(const std::string &prefix, int secs, int nobj, uint64_t objsize, int tno, int nthreads)
{
	auto t0 = std::chrono::steady_clock::now();
	uint64_t i = 0;
	while (std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() < secs) {
		std::string oid = objname(prefix, 100 + ((i * nthreads + tno) % nobj));
		auto a = std::chrono::steady_clock::now();
		int rc;
		const char *k;
		if (i % 2 == 0) {
			ObjectWriteOperation w;
			w.write(0, bl_of(pat(objsize < 4096 ? objsize : 4096, 7, (int)(i % 200))));
			rc = io.operate(oid, &w);
			k = "write";
		} else {
			ObjectReadOperation r;
			bufferlist out, all;
			int rv = 0;
			r.read(0, 4096, &out, &rv);
			rc = io.operate(oid, &r, &all);
			k = "read";
		}
		double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - a).count();
		{
			std::lock_guard<std::mutex> g(out_mu);
			printf("{\"n\":%llu,\"kind\":\"loop\",\"thread\":%d,\"op\":\"%s\",\"oid\":\"%s\",\"rc\":%d,\"ms\":%.1f}\n", (unsigned long long)i, tno, k,
			       oid.c_str(), rc, ms);
			fflush(stdout);
		}
		i++;
		usleep(8000);
	}
}
static void loop_session(const std::string &prefix, int secs, int nobj, uint64_t objsize, int nthreads)
{
	std::vector<std::thread> th;
	for (int t = 0; t < nthreads; t++)
		th.emplace_back(loop_thread, prefix, secs, nobj, objsize, t, nthreads);
	for (auto &t : th)
		t.join();
}

int main(int argc, char **argv)
{
	if (argc < 6) {
		fprintf(stderr, "usage: osdc_probe USER KEYRING POOL SESSION args...\n");
		return 2;
	}
	std::string user = argv[1], keyring = argv[2], pool = argv[3], sess = argv[4];
	int r = cluster.init2(("client." + user).c_str(), "ceph", 0);
	if (r < 0) { fprintf(stderr, "init2 %d\n", r); return 1; }
	cluster.conf_read_file("/etc/ceph/ceph.conf");
	cluster.conf_set("keyring", keyring.c_str());
	cluster.conf_set("ms_client_mode", "crc");
	cluster.conf_set("ms_mon_client_mode", "crc");
	r = cluster.connect();
	if (r < 0) { fprintf(stderr, "connect %d\n", r); return 1; }
	r = cluster.ioctx_create(pool.c_str(), io);
	if (r < 0) { fprintf(stderr, "ioctx %d\n", r); return 1; }
	if (sess == "hdr")
		hdr_session(argv[5], argv[6], strtoull(argv[7], 0, 0));
	else if (sess == "hdr-missing")
		hdr_missing();
	else if (sess == "io")
		io_session(argv[5], strtoull(argv[6], 0, 0));
	else if (sess == "snap") {
		std::vector<uint64_t> sn;
		for (int i = 8; i < argc; i++)
			sn.push_back(strtoull(argv[i], 0, 0));
		snap_session(argv[5], strtoull(argv[6], 0, 0), strtoull(argv[7], 0, 0), sn);
	} else if (sess == "loop")
		loop_session(argv[5], atoi(argv[6]), atoi(argv[7]), strtoull(argv[8], 0, 0), argc > 9 ? atoi(argv[9]) : 4);
	else {
		fprintf(stderr, "unknown session %s\n", sess.c_str());
		return 2;
	}
	io.close();
	cluster.shutdown();
	return 0;
}
CPP_END
}

# ---- network namespace: the client runs in it, tcpdump on the host side of the veth pair -------------------------------------

net_setup() {
  sudo -n ip netns add $NSNAME || die "cannot create the namespace $NSNAME (left over from an earlier run? run: $0 cleanup)"
  sudo -n ip link add $VETH_H type veth peer name $VETH_C
  sudo -n ip link set $VETH_C netns $NSNAME
  sudo -n ip addr add $NET_H/24 dev $VETH_H
  sudo -n ip link set $VETH_H up
  $NS ip addr add $NET_C/24 dev $VETH_C
  $NS ip link set $VETH_C up
  $NS ip link set lo up
  $NS ip route add default via $NET_H
}
net_teardown() {
  sudo -n pkill -INT -f "tcpdump -i $VETH_H" 2>/dev/null
  sudo -n ip netns del $NSNAME 2>/dev/null
  sudo -n ip link del $VETH_H 2>/dev/null
  true
}

# ---- one capture session ----------------------------------------------------------------------------------------------------

SESS=""; SKIND=""; SABOUT=""; SCMDS=(); S_START=""; S_EP0=""
sbegin() { # name kind(probe|cli|backoff) about
  SESS=$1; SKIND=$2; SABOUT=$3; SCMDS=(); S_START=$(date -u +%Y-%m-%dT%H:%M:%SZ); S_EP0=$(epoch)
  : > $WORK/probe/$SESS.jsonl
  sudo -n rm -f $WORK/pcap/$SESS.pcap
  $NS ping -c1 -W1 10.77.0.10 >/dev/null 2>&1; sudo -n ping -c1 -W1 -I $VETH_H $NET_C >/dev/null 2>&1   # warm the ARP caches
  sudo -n tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$SESS.pcap host $NET_C >/dev/null 2>$WORK/pcap/$SESS.err &
  sleep 1.5
}
probe() { # args of osdc_probe after USER KEYRING POOL
  SCMDS+=("osdc_probe $USERN <keyring> $POOL $*")
  $NS $WORK/osdc_probe $USERN $KEYRING $POOL "$@" >> $WORK/probe/$SESS.jsonl 2>> $WORK/probe/$SESS.stderr
  local rc=$?; [ $rc = 0 ] || echo "probe rc=$rc for $*" >&2
}
cli() { # tool args...
  local tool=$1; shift
  SCMDS+=("$tool -n client.$USERN --keyring <keyring> --ms_client_mode crc --ms_mon_client_mode crc $*")
  $NS timeout 120 $tool -n client.$USERN --keyring $KEYRING --ms_client_mode crc --ms_mon_client_mode crc "$@" >> $WORK/probe/$SESS.cli 2>&1
  echo "### rc=$? $tool $*" >> $WORK/probe/$SESS.cli
}
send() {
  sleep 1.5
  sudo -n pkill -INT -f "tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$SESS.pcap"; sleep 1.5
  sudo -n chown -R $(id -un):$(id -gn) $WORK/pcap 2>/dev/null
  local end ep1 dropped
  end=$(date -u +%Y-%m-%dT%H:%M:%SZ); ep1=$(epoch)
  dropped=$(grep -h 'packets dropped by kernel' $WORK/pcap/$SESS.err | awk '{print $1}')
  S_NAME="$SESS" S_KIND="$SKIND" S_ABOUT="$SABOUT" S_START="$S_START" S_END="$end" S_EP0="$S_EP0" S_EP1="$ep1" S_DROP="${dropped:-0}" \
  S_CMDS="$(printf '%s\n' "${SCMDS[@]}")" python3 - <<'PY'
import json, os
w = os.environ["WORK"]
d = dict(kind=os.environ["S_KIND"], about=os.environ["S_ABOUT"], start=os.environ["S_START"], end=os.environ["S_END"],
         epoch0=int(os.environ["S_EP0"]), epoch1=int(os.environ["S_EP1"]), dropped=int(os.environ["S_DROP"]),
         commands=[c for c in os.environ["S_CMDS"].split("\n") if c])
json.dump(d, open("%s/meta/%s.json" % (w, os.environ["S_NAME"]), "w"), indent=1)
PY
  say "session $SESS done: $(stat -c %s $WORK/pcap/$SESS.pcap) bytes, dropped by kernel: ${dropped:-0}, epoch $S_EP0 -> $ep1"
  SESSIONS+=("$SESS")
}
export WORK
SESSIONS=()

# ---- cluster settings the capture changes: saved first, put back exactly (an option that was set before is set again, one that was not is removed)

cfg_set() { # who name value
  local f=$WORK/cfgsave/$1.$2
  mkdir -p $WORK/cfgsave
  [ -f $f ] || $A config dump -f json | python3 -c 'import sys,json;w,n=sys.argv[1:3];print(next((x["value"] for x in json.load(sys.stdin) if x["section"]==w and x["name"]==n),"__UNSET__"))' "$1" "$2" > $f
  $A config set $1 $2 $3 >/dev/null
}
cfg_restore() { # who name
  local f=$WORK/cfgsave/$1.$2
  [ -f $f ] || return 0
  local v; v=$(cat $f)
  if [ "$v" = "__UNSET__" ]; then $A config rm $1 $2 >/dev/null 2>&1; else $A config set $1 $2 "$v" >/dev/null; fi
  rm -f $f
}

# ---- baseline, user, pools, images ----------------------------------------------------------------------------------------------

state_snapshot() { # label: the facts the proof of reversion compares (names of the lab's own users and objects are reduced to a count and a hash)
  local f=$WORK/state-$1.txt
  {
    echo "osd tree:"; $A osd tree -f json | python3 -c 'import sys,json;d=json.load(sys.stdin);print(sorted((n["name"],n.get("status"),n.get("reweight")) for n in d["nodes"] if n["type"]=="osd"))'
    echo "pools:"; $A osd pool ls detail -f json | python3 -c 'import sys,json;print(sorted((p["pool_name"],p["pg_num"],p["size"]) for p in json.load(sys.stdin)))'
    echo "upmap lines: $($A osd dump | grep -c 'pg_upmap')"
    echo "osd flags: $($A osd dump | grep '^flags')"
    $A health detail -f json | python3 -c 'import sys,json,hashlib;d=json.load(sys.stdin);c=sorted(d["checks"]);m=sorted(x["code"] for x in d.get("mutes",[]));print("health checks: %d, sha256 %s; mutes: %d, sha256 %s" % (len(c), hashlib.sha256(" ".join(c).encode()).hexdigest()[:16], len(m), hashlib.sha256(" ".join(m).encode()).hexdigest()[:16]))'
    echo "rbd images: $($R ls $POOL | sort | wc -l)"
    echo "rados objects: $($RD ls | sort | wc -l), sha256 $($RD ls | sort | sha256sum | cut -c1-16)"
    echo "auth entities: $($A auth ls 2>/dev/null | grep '^client\.\|^osd\.\|^mon\.\|^mgr\.' | sort | wc -l), sha256 $($A auth ls 2>/dev/null | grep '^client\.\|^osd\.\|^mon\.\|^mgr\.' | sort | sha256sum | cut -c1-16)"
    echo "config options set: $($A config dump -f json | python3 -c 'import sys,json,hashlib;d=json.load(sys.stdin);print("%d, sha256 %s" % (len(d), hashlib.sha256(json.dumps(sorted((x["section"],x["name"],x["value"]) for x in d)).encode()).hexdigest()[:16]))')"
    echo "backoff and pool-delete settings: osd_backoff_on_peering=$($A config get osd osd_backoff_on_peering) osd_backoff_on_degraded=$($A config get osd osd_backoff_on_degraded) mon_allow_pool_delete=$($A config get mon mon_allow_pool_delete)"
  } > $f 2>&1
}

make_user() {
  # a user of its own, with the caps of the stock RBD profile on the two pools of the capture, never the lab's regular users
  $A auth get client.$USERN >/dev/null 2>&1 && die "client.$USERN exists already (left over? run: $0 cleanup)"
  mkdir -p $WORK/keys; chmod 700 $WORK/keys
  $A auth get-or-create client.$USERN mon 'profile rbd' osd "profile rbd pool=$POOL, profile rbd pool=$DPOOL" -o $KEYRING >/dev/null || die "cannot create client.$USERN"
  sudo -n chown $(id -u):$(id -g) $KEYRING; chmod 600 $KEYRING
  USER_CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  say "created client.$USERN (key in $KEYRING, mode 600, never printed)"
}

make_pool() {
  $A osd pool create $DPOOL 8 8 replicated >/dev/null 2>&1 || die "cannot create pool $DPOOL"
  $A osd pool application enable $DPOOL rbd >/dev/null 2>&1
}

mkimg() { # short name, then rbd create args
  local n=$1; shift
  $R create "$@" $POOL/$(iname $n) >/dev/null 2>&1 || die "rbd create $n failed"
}

make_images() {
  mkimg f01 --size 1M --object-size 4K --image-feature layering
  mkimg f05 --size 2M --object-size 8K --image-feature layering,exclusive-lock
  mkimg f21 --size 4M --object-size 16K --image-feature layering,deep-flatten
  mkimg f3d --size 8M --object-size 64K
  mkimg f45 --size 2M --object-size 32K --image-feature layering,exclusive-lock,journaling
  mkimg dp --size 2M --object-size 8K --image-feature layering --data-pool $DPOOL
  mkimg str --size 4M --object-size 16K --image-feature layering,striping --stripe-unit 4096 --stripe-count 4
  mkimg snap --size 4M --object-size 16K --image-feature layering,deep-flatten
  mkimg lock --size 2M --object-size 32K --image-feature layering,deep-flatten
  mkimg io --size 1M --object-size 16K --image-feature layering
  # a clone of f01 (parent info reveals it: its feature word stays 0x1, rbd-format2.md 3.3 rule 6)
  $R snap create $POOL/$(iname f01)@c1 >/dev/null && $R snap protect $POOL/$(iname f01)@c1 >/dev/null || die "snapshot of f01"
  $R clone $POOL/$(iname f01)@c1 $POOL/$(iname clone) --image-feature layering >/dev/null 2>&1 || die "clone"
  # the image with snapshots: objects exist before the snapshots (so a later write has something to clone), one snapshot is removed
  # again (a gap in the ids: the snapshot context keeps its sequence)
  local sid; sid=$($R info --format json $POOL/$(iname snap) | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
  for o in 0 1; do
    python3 -c "import sys;sys.stdout.buffer.write(bytes(((i*7+3)%251) for i in range(5000)))" | $RD put rbd_data.$sid.$(printf '%016x' $o) - || die "seed object"
  done
  for s in s1 s2 s3; do $R snap create $POOL/$(iname snap)@$s >/dev/null || die "snap create $s"; done
  $R snap rm $POOL/$(iname snap)@s2 >/dev/null || die "snap rm s2"
  # the default-feature image has been written once by a client that took and released the exclusive lock: the lock record stays,
  # with its type and tag and no locker (rbd-format2.md 2.7)
  $R bench --io-type write --io-size 4096 --io-total 4096 $POOL/$(iname f3d) >/dev/null 2>&1 || die "rbd bench on f3d"
  # an advisory lock held by somebody else on the image `lock`
  $R lock add $POOL/$(iname lock) vec-osdc-cookie >/dev/null || die "rbd lock add"
}

pattern_file() { # out size, then segments "off,len,mul,add"...
  local out=$1 size=$2; shift 2
  python3 - "$out" "$size" "$@" <<'PY'
import sys
out, size = sys.argv[1], int(sys.argv[2])
b = bytearray(size)
for s in sys.argv[3:]:
    off, ln, mul, add = (int(x) for x in s.split(","))
    for o in range(off, off + ln):
        b[o] = (o * mul + add) % 251
open(out, "wb").write(b)
PY
}

make_patterns() {
  mkdir -p $WORK/pat
  pattern_file $WORK/pat/pat12 65536 0,4096,7,3 6000,5000,13,5 20480,8192,11,7 61440,1000,3,1
  pattern_file $WORK/pat/pat14 262144 0,16384,7,3 20000,30000,13,5 200000,4000,5,2
  pattern_file $WORK/pat/pat16 1048576 100,70000,7,3 300000,65536,11,7 1040000,8000,3,9
  $R import --image-format 2 --object-size 4K --image-feature layering $WORK/pat/pat12 $POOL/$(iname pat12) >/dev/null 2>&1 || die "import pat12"
  $R import --image-format 2 --object-size 16K --image-feature layering $WORK/pat/pat14 $POOL/$(iname pat14) >/dev/null 2>&1 || die "import pat14"
  $R import --image-format 2 --object-size 64K --image-feature layering $WORK/pat/pat16 $POOL/$(iname pat16) >/dev/null 2>&1 || die "import pat16"
}

# ground truth of every image taken with the stock tools (not with our own code)
make_gt() {
  mkdir -p $WORK/gt
  local pools; pools=$($A osd pool ls detail -f json)
  for n in $IMGS $PATS io; do
    local full=$POOL/$(iname $n)
    python3 - "$n" "$(iname $n)" <<PY
import json, subprocess, sys
short, name = sys.argv[1], sys.argv[2]
def run(*a):
    return json.loads(subprocess.check_output(["sudo", "-n"] + list(a)))
info = run("rbd", "info", "--format", "json", "$full")
snaps = run("rbd", "snap", "ls", "--format", "json", "$full")
locks = run("rbd", "lock", "ls", "--format", "json", "$full")
pools = json.loads('''$pools''')
bits = dict(layering=1, striping=2, **{"exclusive-lock": 4, "object-map": 8, "fast-diff": 16, "deep-flatten": 32, "journaling": 64,
            "data-pool": 128, "operations": 256, "migrating": 512, "non-primary": 1024, "dirty-cache": 2048})
mask = 0
for f in info.get("features", []):
    mask |= bits[f]
gt = dict(name=name, id=info["id"], size=info["size"], order=info["order"], object_size=info["object_size"], objects=info["objects"],
          block_name_prefix=info["block_name_prefix"], features=info.get("features", []), features_mask=mask,
          op_features=info.get("op_features", []), flags=info.get("flags", []), stripe_unit=info.get("stripe_unit", info["object_size"]),
          stripe_count=info.get("stripe_count", 1), snaps=[dict(id=s["id"], name=s["name"], size=s["size"]) for s in snaps],
          locks=len(locks) if isinstance(locks, list) else len(locks.get("locks", [])) if isinstance(locks, dict) else 0)
if "parent" in info:
    gt["parent"] = dict(image=info["parent"]["image"], snapshot=info["parent"]["snapshot"])
if "data_pool" in info:
    gt["data_pool_id"] = [p["pool_id"] for p in pools if p["pool_name"] == info["data_pool"]][0]
json.dump(gt, open("$WORK/gt/%s.json" % name, "w"), indent=1, sort_keys=True)
PY
  done
}

# ---- the sessions -------------------------------------------------------------------------------------------------------------

hdr_sessions() {
  for n in $IMGS; do
    local name; name=$(iname $n)
    local id feat
    id=$(python3 -c "import json;d=json.load(open('$WORK/gt/$name.json'));print(d['id'])")
    feat=$(python3 -c "import json;d=json.load(open('$WORK/gt/$name.json'));print(d['features_mask'])")
    sbegin hdr-$name probe "the open of $name: get_id, the eight-call header read (reader and writer form), extra calls, lock get_info"
    probe hdr $name $id $feat
    send
  done
  sbegin hdr-missing probe "get_id and the header read of an image that does not exist: -ENOENT for the whole message"
  probe hdr-missing x
  send
}

io_session() {
  local name; name=$(iname io)
  local id; id=$(python3 -c "import json;print(json.load(open('$WORK/gt/$name.json'))['id'])")
  sbegin io-plain probe "object operations on rbd_data objects of an image with 16 KiB objects: READ (missing, short, exact, past the end, whole), WRITE, hole, SPARSE_READ, STAT, ZERO, ZERO to the end, TRUNCATE, DELETE, no-ops on an absent object"
  probe io rbd_data.$id 16384
  send
  # snapshots: the context comes from the header read of the image (the log of its header session)
  local sname; sname=$(iname snap)
  local sid; sid=$(python3 -c "import json;print(json.load(open('$WORK/gt/$sname.json'))['id'])")
  local ctx; ctx=$(python3 - "$WORK/probe/hdr-$sname.jsonl" <<'PY'
import json, struct, sys
for ln in open(sys.argv[1]):
    d = json.loads(ln)
    if d["label"] == "header8-writer":
        out = bytes.fromhex(d["calls"][4]["out"])
        seq, n = struct.unpack_from("<QI", out)
        print(seq, *struct.unpack_from("<%dQ" % n, out, 12))
PY
)
  sbegin io-snap probe "writes with the image's snapshot context (a clone is made), reads of snapshots, delete that leaves a whiteout, an empty context"
  probe snap rbd_data.$sid 16384 $ctx
  send
}

objects_sessions() {
  for n in $PATS; do
    local name; name=$(iname $n)
    local id; id=$(python3 -c "import json;print(json.load(open('$WORK/gt/$name.json'))['id'])")
    mkdir -p $WORK/objects/$n
    local objs; objs=$($RD ls | grep "^rbd_data\.$id\." | sort)
    sbegin objects-$n cli "rados get of every data object of the patterned image $n, and of one that does not exist"
    for o in $objs; do
      cli rados -p $POOL get $o $WORK/objects/$n/$o
    done
    cli rados -p $POOL get rbd_data.$id.00000000000000ff $WORK/objects/$n/absent.out
    rm -f $WORK/objects/$n/absent.out
    send
  done
}

# backoff sessions: a steady load while an OSD restarts, and while an OSD is marked out and in again. The OSDs only answer a request
# to a PG that is not active with a backoff when they are told to (osd_backoff_on_peering), so that setting is turned on for the
# duration of these two sessions and removed afterwards.
backoff_config_on() {
  CONFIG_TOUCHED=1
  cfg_set osd osd_backoff_on_peering true
  cfg_set osd osd_backoff_on_degraded true
}
backoff_config_off() {
  cfg_restore osd osd_backoff_on_peering
  cfg_restore osd osd_backoff_on_degraded
  CONFIG_TOUCHED=""
}
wait_clean() { # up to 120 s until every PG is active+clean and all OSDs are up and in
  local i
  for i in $(seq 1 60); do
    if $A pg stat -f json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
s = d.get("pg_summary", d)
tot = s["num_pgs"]
ac = sum(x["num"] for x in s["num_pg_by_state"] if x["name"] == "active+clean")
sys.exit(0 if ac == tot else 1)'; then
      if $A osd stat -f json | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(0 if d["num_osds"]==d["num_up_osds"]==d["num_in_osds"] else 1)'; then return 0; fi
    fi
    sleep 2
  done
  return 1
}
FSID=""
osd_unit() { echo "ceph-$FSID@osd.$1.service"; }

backoff_session() { # name action(restart|out) osd secs
  local name=$1 action=$2 osd=$3 secs=$4
  sbegin $name backoff "a steady load of writes and reads over many PGs while osd.$osd is $( [ $action = restart ] && echo restarted || echo 'marked out and in again'); OSDs told to back off on peering"
  probe loop wrtest-osdc-loop $secs 64 4096 6 &
  local lp=$!
  sleep 6
  if [ $action = restart ]; then
    sudo -n systemctl restart $(osd_unit $osd)
  else
    $A osd out $osd >/dev/null
    sleep 14
    $A osd in $osd >/dev/null
  fi
  wait $lp
  wait_clean || echo "WARNING: PGs not clean 120 s after $name" >&2
  send
}

# ---- clean-up and the proof that nothing was left ------------------------------------------------------------------------------

cleanup() {
  say "clean-up"
  net_teardown
  backoff_config_off
  # OSDs up and in, whatever happened
  for o in 0 1 2; do $A osd in osd.$o >/dev/null 2>&1; done
  for o in 0 1 2; do
    sudo -n systemctl is-active --quiet $(osd_unit $o) || sudo -n systemctl start $(osd_unit $o)
  done
  # lock, clone, snapshots, images
  $R lock ls $POOL/$(iname lock) 2>/dev/null | awk 'NR>1 && NF>=2 {print $2, $1}' | while read -r locker id; do
    $R lock rm $POOL/$(iname lock) "$id" "$locker" >/dev/null 2>&1
  done
  $R rm $POOL/$(iname clone) >/dev/null 2>&1
  $R snap unprotect $POOL/$(iname f01)@c1 >/dev/null 2>&1
  for n in $IMGS $PATS io; do
    $R snap purge $POOL/$(iname $n) >/dev/null 2>&1
    $R rm $POOL/$(iname $n) >/dev/null 2>&1
  done
  # raw objects of the sessions (the seeds of `snap`, the load of the backoff sessions)
  for o in $($RD ls 2>/dev/null | grep -E '^wrtest-osdc-|^rbd_data\.' ); do
    case "$o" in
      wrtest-osdc-*) $RD rm "$o" >/dev/null 2>&1 ;;
    esac
  done
  if $A osd pool ls | grep -qx $DPOOL; then
    cfg_set mon mon_allow_pool_delete true
    $A osd pool delete $DPOOL $DPOOL --yes-i-really-really-mean-it >/dev/null 2>&1
    cfg_restore mon mon_allow_pool_delete
  fi
  $A auth del client.$USERN >/dev/null 2>&1
  wait_clean || true
}

# stray rbd_data objects of our images: removed with their image; the ids are remembered by name only
verify_gone() {
  USER_GONE=""
  if $A auth get client.$USERN >/dev/null 2>&1; then die "client.$USERN still exists after the clean-up"; fi
  $A auth ls 2>/dev/null | grep -q "client.$USERN" && die "client.$USERN is still in the auth list"
  USER_GONE="ceph auth get client.$USERN fails (ENOENT) and the entity is not in the auth list, checked $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  $R ls $POOL | grep -q wrtest-osdc && die "an image of the capture is left"
  $RD ls | grep -q wrtest-osdc && die "an object of the capture is left"
  $A osd pool ls | grep -qx $DPOOL && die "the pool $DPOOL is left"
  ip netns list | grep -q $NSNAME && die "the namespace is left"
  pgrep -f "tcpdump -i $VETH_H" >/dev/null && die "a tcpdump is still running"
  return 0
}

# ---- plan.json for the extractor and the whole run ---------------------------------------------------------------------------------

write_plan() {
  local sessions; sessions=$(printf '%s\n' "${SESSIONS[@]}")
  S="$sessions" USER_CREATED="$USER_CREATED" USER_GONE="$USER_GONE" CEPHV="$($A --version | awk '{print $3}')" python3 - <<PY
import json, os
w = os.environ["WORK"]
sessions = [s for s in os.environ["S"].split("\n") if s]
imgs = []
for n in "$IMGS".split():
    d = dict(name="wrtest-osdc-" + n, short=n)
    if n == "lock":
        d["lock"] = "foreign"
    imgs.append(d)
pats = []
rec = dict(pat12=(12, 65536, [[0,4096,7,3],[6000,5000,13,5],[20480,8192,11,7],[61440,1000,3,1]]),
           pat14=(14, 262144, [[0,16384,7,3],[20000,30000,13,5],[200000,4000,5,2]]),
           pat16=(16, 1048576, [[100,70000,7,3],[300000,65536,11,7],[1040000,8000,3,9]]))
for n, (order, size, segs) in rec.items():
    g = json.load(open("%s/gt/wrtest-osdc-%s.json" % (w, n)))
    pats.append(dict(name=n, image="wrtest-osdc-" + n, id=g["id"], prefix=g["block_name_prefix"], order=order, size=size, segments=segs))
plan = dict(sessions=sessions, images=imgs, patterns=pats,
            index=dict(version=1, ceph_release=os.environ["CEPHV"], pool="$POOL", data_pool="$DPOOL",
                       about="OSD and RBD captures of the stock client library in crc mode (module vectors-c)",
                       user=dict(entity="client.$USERN", caps="mon 'profile rbd', osd 'profile rbd pool=$POOL, profile rbd pool=$DPOOL'",
                                 created=os.environ["USER_CREATED"], deleted=True, verified_gone=os.environ["USER_GONE"],
                                 key_published=False)))
json.dump(plan, open(w + "/plan.json", "w"), indent=1)
PY
}

run_all() {
  local out=${1:-$WORK/osdc}
  mkdir -p $WORK/pcap $WORK/probe $WORK/meta $WORK/gt $WORK/objects
  FSID=$($A fsid)
  trap 'cleanup' EXIT
  build_probe
  state_snapshot before
  [ -z "$($A osd tree -f json | grep -c '"status": "down"' | grep -v '^0$')" ] || die "an OSD is down before the start"
  make_user
  make_pool
  net_setup
  make_images
  make_patterns
  make_gt
  hdr_sessions
  io_session
  objects_sessions
  backoff_config_on
  backoff_session backoff-restart restart 2 34
  backoff_session backoff-out out 1 40
  backoff_config_off
  trap - EXIT
  cleanup
  state_snapshot after
  verify_gone
  write_plan
  mkdir -p "$out"
  {
    echo "# revert proof of capture_osdc.sh, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# the facts of the lab before the run and after the clean-up (osd tree, pools, upmap lines, flags, health checks, images, objects, auth entities,"
    echo "# every explicitly set configuration option, the backoff and pool-delete settings), then the lines that differ"
    echo "--- before:"; cat $WORK/state-before.txt
    echo "--- after:"; cat $WORK/state-after.txt
    echo "--- diff:"
    diff $WORK/state-before.txt $WORK/state-after.txt && echo "(none)"
    echo "--- throwaway user: $USER_GONE"
  } > "$out/revert-proof.txt"
  python3 -I $SCRIPTS/check_osdc.py extract --work $WORK --out "$out" || die "the extraction failed"
  # the tree must not contain the throwaway key (it never held it, this proves it)
  local key; key=$(awk '/key =/ {print $3}' $KEYRING 2>/dev/null)
  if [ -n "$key" ] && grep -rqF "$key" "$out"; then die "the user's key text is in the vector tree"; fi
  rm -f $KEYRING
  python3 -I $SCRIPTS/check_osdc.py check --dir "$out"
  say "done: $out"
}

case ${1:-help} in
  run) run_all "${2:-}";;
  cleanup) FSID=$($A fsid); cleanup;;
  nettest) # the namespace reaches the monitor and an OSD port of the lab (no user, no capture)
    trap net_teardown EXIT; net_setup
    $NS ping -c1 -W2 10.77.0.10 >/dev/null && echo "ping ok" || echo "ping FAILED"
    $NS timeout 5 bash -c 'exec 3<>/dev/tcp/10.77.0.10/3300; head -c 8 <&3' 2>/dev/null | head -c 8; echo " <- banner of the monitor";;
  *) sed -n '2,30p' "$0";;
esac
