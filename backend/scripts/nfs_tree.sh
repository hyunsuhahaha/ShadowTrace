#!/usr/bin/env bash
# Mounts one NFS export read-only to a throwaway mount point, lists its full
# contents tagged D|/F| (same format as the WinRM/SSH/FTP tree commands), and
# always unmounts + removes the mount point on the way out -- showmount -e
# only lists the exports themselves, not what's inside them.
set -uo pipefail

host="$1"
export_path="$2"
max_entries=2000

mount_point=$(mktemp -d /tmp/oscp-nfs-XXXXXX) || exit 1
cleanup() { umount "$mount_point" 2>/dev/null; rmdir "$mount_point" 2>/dev/null; }
# ponytail: if the app's "stop" button is hit while mount(2) is genuinely
# stuck (NFS's well-known "survives kill -9" D-state hang), this trap may
# never get to run and the empty mount_point dir leaks in /tmp -- harmless
# litter, not a real mount leak (confirmed via findmnt), and not solvable
# from userspace. The wall-clock timeout above is what actually prevents
# the hang in the unattended/common case.
trap cleanup EXIT

connect_timeout=15
# soft/timeo/retrans only bound retries on an NFS mount that's already
# talking to the server -- a target with nothing listening on the NFS ports
# at all can hang the initial mount(2) call well past that (verified live:
# a real unreachable HTB target hung for 20+ seconds with no sign of
# stopping), so the whole attempt also gets a hard wall-clock timeout.
if ! timeout "$connect_timeout" mount -t nfs \
    -o ro,soft,timeo=50,retrans=2,nolock "${host}:${export_path}" "$mount_point" 2>&1; then
  echo "[-] ${host}:${export_path} 마운트 실패 (또는 ${connect_timeout}초 내 응답 없음)" >&2
  exit 1
fi

find "$mount_point" -mindepth 1 \( -type d -printf 'D|%P\n' \) -o -printf 'F|%P\n' \
  2>/dev/null | head -n "$max_entries"
