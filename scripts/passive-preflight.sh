#!/usr/bin/env bash
set -u

kernel_release="$(uname -r)"
headers_dir="/lib/modules/$kernel_release/build"
ready=1

printf 'ShadowTrace passive observer preflight\n'
printf '  kernel: %s\n' "$kernel_release"

if /usr/bin/python3 -c 'import bcc' >/dev/null 2>&1; then
  printf '  BCC Python bindings: ready\n'
else
  printf '  BCC Python bindings: missing\n'
  printf '  install: sudo apt update && sudo apt install python3-bpfcc\n'
  ready=0
fi

if [ -d "$headers_dir" ]; then
  printf '  matching kernel headers: %s\n' "$headers_dir"
else
  printf '  matching kernel headers: missing (%s)\n' "$headers_dir"
  ready=0
  if apt-cache show "linux-headers-$kernel_release" >/dev/null 2>&1; then
    printf '  install: sudo apt update && sudo apt install linux-headers-%s\n' \
      "$kernel_release"
    printf '  reboot: not required when uname -r remains %s\n' "$kernel_release"
  else
    printf '  exact header package is not present in the current APT metadata.\n'
    printf '  install current Kali kernel + headers:\n'
    printf '    sudo apt update\n'
    printf '    sudo apt install linux-image-amd64 linux-headers-amd64\n'
    printf '    sudo reboot\n'
    printf '  after reboot, verify: uname -r && test -d /lib/modules/$(uname -r)/build\n'
  fi
fi

if [ "$(id -u)" -eq 0 ]; then
  if [ -r /sys/kernel/tracing/events/sched/sched_process_exec/format ] || \
     [ -r /sys/kernel/debug/tracing/events/sched/sched_process_exec/format ]; then
    printf '  tracepoints: readable\n'
  else
    printf '  tracepoints: unavailable; ensure tracefs/debugfs is mounted\n'
    ready=0
  fi
else
  printf '  privilege: run the observer through ./scripts/start.sh (sudo required)\n'
fi

if [ "$ready" -eq 1 ]; then
  printf '  result: ready for BPF compile/load\n'
  exit 0
fi
printf '  result: not ready; no installation was attempted\n'
exit 1
