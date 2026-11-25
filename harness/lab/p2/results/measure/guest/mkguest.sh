#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mkguest.sh - build the kernel and the initramfs of the kernel-client guest (design 14.4) INSIDE the lab VM, from what it already runs: its own kernel
# and modules (the Ubuntu 24.04 6.8 kernel, the client the lab uses as its oracle), a static busybox, and rdbench.c compiled static. Run in the lab VM as root
# (tools/mguest.sh does it over ssh): mkguest.sh SRCDIR OUTDIR. Produces OUTDIR/vmlinuz and OUTDIR/initrd.img; touches nothing else.
# SRCDIR holds init and rdbench.c. Needs: gcc with static libc, zstd, cpio, gzip, busybox-static (apt-get install busybox-static when missing).
set -euo pipefail
src=${1:?SRCDIR}
out=${2:?OUTDIR}
kver=$(uname -r)
[ -x /bin/busybox ] || apt-get install -y busybox-static > /dev/null
bb=$(command -v busybox)
[ "$("$bb" --list | grep -cx insmod)" = 1 ] || { echo "mkguest: this busybox has no insmod" >&2; exit 1; }
rm -rf "$out"
mkdir -p "$out/root/bin" "$out/root/lib/modules" "$out/root/proc" "$out/root/sys" "$out/root/dev"
install -m 0755 "$bb" "$out/root/bin/busybox"
gcc -O2 -static -Wall -Wextra -o "$out/root/bin/rdbench" "$src/rdbench.c"
install -m 0755 "$src/init" "$out/root/init"
: > "$out/root/modules.list"
# every module in dependency order: modprobe says what it would load, in order ("insmod <path>" lines; builtin ones are skipped)
for m in qemu_fw_cfg virtio_pci virtio_net libcrc32c crc32c_generic cbc aes_generic ecb hmac sha256_generic sha512_generic rbd; do
	{ modprobe -S "$kver" --show-depends "$m" 2> /dev/null || true; } | sed -n 's/^insmod //p' | while read -r path rest; do
		base=$(basename "$path")
		base=${base%.zst}
		if [ "$(grep -cx "$base" "$out/root/modules.list")" = 0 ]; then
			case $path in
				*.zst) zstd -dcq "$path" > "$out/root/lib/modules/$base";;
				*.xz) xz -dc "$path" > "$out/root/lib/modules/$base";;
				*) cp "$path" "$out/root/lib/modules/$base";;
			esac
			echo "$base" >> "$out/root/modules.list"
		fi
	done
done
[ "$(grep -cx 'rbd.ko' "$out/root/modules.list")" = 1 ] || { echo "mkguest: no rbd module for $kver" >&2; exit 1; }
[ "$(grep -cx 'libceph.ko' "$out/root/modules.list")" = 1 ] || { echo "mkguest: no libceph module for $kver" >&2; exit 1; }
(cd "$out/root" && find . | cpio -o -H newc --quiet | gzip -9 > "$out/initrd.img")
cp "/boot/vmlinuz-$kver" "$out/vmlinuz"
chmod 644 "$out/vmlinuz" "$out/initrd.img"
echo "mkguest: kernel $kver, $(wc -l < "$out/root/modules.list") modules ($(tr '\n' ' ' < "$out/root/modules.list")), initramfs $(stat -c %s "$out/initrd.img") bytes"
sha256sum "$out/vmlinuz" "$out/initrd.img"
