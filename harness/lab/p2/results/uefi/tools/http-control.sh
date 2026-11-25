#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# http-control.sh - the control experiment for the intermittent "boot stalls after the menu of GRUB" finding of row U1: the very same flow
# (OVMF, ipxe.efi by PXE, sanboot over the lab NIC, GRUB, kernel, initramfs) with iPXE's OWN stock HTTP SAN protocol instead of rbd://.
# If the stock protocol stalls as often, the finding is about iPXE + OVMF + the NIC, not about the rbd driver; if it never does, it is
# about the driver.
#
#   http-control.sh start            export the Linux image out of the lab cluster (rbd export, by the lab's own tools) into a file in the lab
#                                    VM and serve it there with a small HTTP server that knows Range requests (iPXE's HTTP SAN reads by range)
#   http-control.sh run N            N guests, each a row HTTP-r<i> of the evidence directory: sanboot http://10.77.0.10:8088/linux.raw, success =
#                                    the initramfs' table hook ran, i.e. GRUB loaded the kernel and the initramfs through the SAN device and the kernel booted
#                                    (the hook finds no table: expected here, there is no rbd driver in this flow)
#   http-control.sh stop             stop the server and delete the exported file
#
# Needs P2_LAB_DIR, P2Q_WORK, P2U_OUT (box-env.sh). The image holds no key; the server listens on the lab's private layer 2 only.
set -euo pipefail
LC_ALL=C
export LC_ALL
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2_LAB_DIR:?}"
: "${P2Q_WORK:?}"
repo=${P2U_REPO:-$(cd "$here/../../../../../.." && pwd)}
P2U=$here/p2u.sh
IMG=${P2U_LIN:-wrtest-p2-lin-uefi}
POOL=${P2U_POOL:-winrbd}
IP=${P2U_IP:-10.77.0.31}
PORT=8088
lab() { bash "$P2U" lab "$@"; }

case ${1:-} in
start)
    lab "sudo rbd export --no-progress $POOL/$IMG /tmp/wr-http-control.raw && sudo chown lab /tmp/wr-http-control.raw && ls -l /tmp/wr-http-control.raw"
    lab 'cat > /tmp/wr-range-http.py' <<'PY'
import http.server, os, re, sys
PATH = "/tmp/wr-http-control.raw"
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def do_HEAD(self):
        self.send_response(200); self.send_header("Content-Length", str(os.path.getsize(PATH)))
        self.send_header("Accept-Ranges", "bytes"); self.end_headers()
    def do_GET(self):
        size = os.path.getsize(PATH)
        m = re.match(r"bytes=(\d*)-(\d*)", self.headers.get("Range", ""))
        if m and (m.group(1) or m.group(2)):
            a = int(m.group(1)) if m.group(1) else max(0, size - int(m.group(2)))
            b = int(m.group(2)) if (m.group(1) and m.group(2)) else size - 1
            b = min(b, size - 1)
            self.send_response(206); self.send_header("Content-Range", "bytes %d-%d/%d" % (a, b, size))
        else:
            a, b = 0, size - 1
            self.send_response(200)
        self.send_header("Content-Length", str(b - a + 1)); self.send_header("Accept-Ranges", "bytes"); self.end_headers()
        with open(PATH, "rb") as f:
            f.seek(a)
            left = b - a + 1
            while left > 0:
                d = f.read(min(1 << 20, left))
                if not d:
                    break
                try:
                    self.wfile.write(d)
                except OSError:
                    return
                left -= len(d)
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
S(("10.77.0.10", 8088), H).serve_forever()
PY
    lab '(nohup python3 /tmp/wr-range-http.py > /tmp/wr-range-http.log 2>&1 &) ; sleep 2; ss -ltn | grep -c ":8088 "'
    ;;
run)
    n=${2:?usage: http-control.sh run N}
    export P2U_OUT
    mkdir -p -m 700 "$P2U_OUT/.expect"
    bash "$repo/harness/lab/p2/qemu/gen-script.sh" -o "$P2U_OUT/.expect/http-control.ipxe" --row U1 --ip "$IP" --no-key --action sanboot \
        --uri "rbd://x@10.77.0.10:3300/$POOL/$IMG"
    sed -i "s#^sanboot rbd://.* || goto san-fail#sanboot http://10.77.0.10:$PORT/linux.raw || goto san-fail#" "$P2U_OUT/.expect/http-control.ipxe"
    grep -q "^sanboot http://" "$P2U_OUT/.expect/http-control.ipxe" || { echo "http-control.sh: could not rewrite the sanboot line" >&2; exit 2; }
    i=1
    while [ "$i" -le "$n" ]; do
        bash "$P2U" row "HTTP-r$i" uefi-pxe --profile control -- --row U1 --ip "$IP" --script "$P2U_OUT/.expect/http-control.ipxe" \
            --expect marker --marker 'WRBOOT-TABLE'  \
            --fail-marker 'error: failure reading sector|Failed to boot both default|Kernel panic' --timeout 300 || true
        i=$((i + 1))
    done
    ;;
stop)
    # two calls: a pkill -f whose own command line also holds the plain name would kill the shell that runs it, and the rm after it would never run
    lab "pkill -f 'python3 /tmp/[w]r-range-http' || true"
    lab "rm -f /tmp/wr-http-control.raw /tmp/wr-range-http.py /tmp/wr-range-http.log; ls /tmp | grep -c '^wr-' || true"
    ;;
*) sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
