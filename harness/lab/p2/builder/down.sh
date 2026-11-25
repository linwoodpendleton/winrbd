#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# down.sh - destroy the Phase 2 builder: power the guest off, delete its disk, key and staged trees, the repository copy, the results
# and the logs, remove the state directory, and check that no process of it is left. Nothing outside BUILDER_DIR is touched, and only
# when BUILDER_DIR carries the marker file that up.sh wrote.
#
#   down.sh [--keep-image] [--keep-out] [--keep-logs]
#
#   --keep-image   keep the cached cloud image (ci26/dl) so that the next up.sh does not copy or download it again
#   --keep-out     keep out/ (the build results: ipxe.efi, undionly.kpxe, ... and their reports)
#   --keep-logs    keep logs/ (and the ci26_vm.sh logs under ci26/logs)
#
# With BUILDER_HOST (from your machine) the repository is staged on the box again first, because the script that runs there lives in the
# staged copy; it deletes that copy as its last step. The environment is the one of up.sh (BUILDER_DIR is required with BUILDER_HOST).
#
# Exit status: 0 destroyed and no process left; 1 something of the builder is still running or a directory could not be removed;
# 2 refused (not a builder directory, a run is in progress, bad environment).

set -eu
set -o pipefail
LC_ALL=C
export LC_ALL

DOWN_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# the shared functions; sourcing up.sh does not run its main
# shellcheck source=up.sh
. "$DOWN_HERE/up.sh"

# the pids of this process and of its ancestors (the shell that runs us, the ssh session that started it): they carry BUILDER_DIR in their
# command lines and are not "left over"
own_pids() {
	local p=$$ pp
	while b_is_uint "$p" && [ "$p" -gt 1 ]; do
		echo "$p"
		pp=$(awk '$1 == "PPid:" { print $2 }' "/proc/$p/status" 2>/dev/null || true)
		[ -n "$pp" ] || break
		p=$pp
	done
}

# processes whose command line names something under BUILDER_DIR, other than ours: this process, its ancestors (the shell and the ssh
# session that started it) and the forks of this very script (command substitutions and pipeline stages carry the same command line).
# ps and a fixed-string match (pgrep -f would match its own command line)
left_over() {
	local own mine l pid args
	own=" $(own_pids | tr '\n' ' ') "
	mine=$(tr '\0' ' ' </proc/$$/cmdline | sed 's/ *$//')
	ps -eo pid=,args= | while IFS= read -r l; do
		pid=$(echo "$l" | awk '{print $1}')
		args=$(echo "$l" | sed 's/^ *[0-9][0-9]* *//; s/ *$//')
		case $own in *" $pid "*) continue ;; esac
		[ "$args" != "$mine" ] || continue
		case $l in *"$BUILDER_DIR/"* | *"$BUILDER_DIR "*) echo "$l" ;; esac
	done
}

down_main() {
	local keep_image=0 keep_out=0 keep_logs=0 a rc=0 left d
	for a in "$@"; do
		case $a in
		--keep-image) keep_image=1 ;;
		--keep-out) keep_out=1 ;;
		--keep-logs) keep_logs=1 ;;
		-h | --help) sed -n '4,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) b_die "unknown argument '$a' (--keep-image, --keep-out, --keep-logs)" ;;
		esac
	done
	if b_remote; then
		b_init_env
		B_FETCH=none
		b_remote_run down.sh "$@"
		exit $?
	fi
	b_init_env
	d=$BUILDER_DIR
	if [ ! -e "$d" ]; then
		b_note "nothing to destroy at $d"
	else
		b_need_marker
		# ci26_vm.sh refuses while a run holds its lock (no pulling the disk from under a build) and only deletes its known sub-directories
		if [ -d "$d/ci26" ]; then
			if [ "$keep_image" = 0 ] && [ "$keep_logs" = 0 ]; then
				ci26 destroy --purge
			else
				# the guest, its key and its staged trees go; image and logs are removed one by one, each unless asked to keep (ci26 destroy
				# without --purge would keep both, and --purge would take both: the two flags are independent). The ci26 marker and the
				# lock file stay with whatever is kept: they let a later down.sh or up.sh recognise the directory.
				ci26 destroy
				[ "$keep_image" = 1 ] || rm -rf -- "${d:?}/ci26/dl"
				[ "$keep_logs" = 1 ] || rm -rf -- "${d:?}/ci26/logs"
			fi
		fi
		# fixed names, nothing computed from outside input
		rm -rf -- "${d:?}/stage" "${d:?}/ready"
		[ "$keep_out" = 1 ] || rm -rf -- "${d:?}/out"
		[ "$keep_logs" = 1 ] || rm -rf -- "${d:?}/logs"
		if [ "$keep_image" = 1 ] || [ "$keep_out" = 1 ] || [ "$keep_logs" = 1 ]; then
			b_note "kept (by request): $(cd "$d" && for e in * ; do [ -e "$e" ] && printf '%s ' "$e"; done)"
		else
			rm -f -- "$d/$B_MARKER"
			rmdir "$d" 2>/dev/null || { b_note "$d still holds other files, left in place: $(ls -A "$d" | tr '\n' ' ')"; rc=1; }
		fi
	fi
	left=$(left_over || true)
	if [ -n "$left" ]; then
		b_note "processes that still name $d:"
		echo "$left" | cut -c1-200 >&2
		rc=1
	else
		b_note "no process of the builder is left"
	fi
	[ "$rc" = 0 ] && b_note "destroyed: $d"
	return "$rc"
}

# one line: bash has parsed all of it before down_main runs, so the deletion of the staged copy that holds this very file cannot be read
# as the next command
down_main "$@"; exit $?
