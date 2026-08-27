#!/usr/bin/env python3
"""Capture local Nmap exec/write/exit events without wrapping the shell."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import signal
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from bcc import BPF
except ImportError:
    raise SystemExit("python3-bpfcc is required for passive capture")

BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_EXEC 1
#define EVENT_WRITE 2
#define EVENT_EXIT 3
#define CHUNK_SIZE 4096

struct event_t {
    u32 kind;
    u32 pid;
    u32 uid;
    s32 fd;
    s32 exit_code;
    u32 size;
    char data[CHUNK_SIZE];
};

BPF_HASH(tracked, u32, u8);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 key = 0;
    struct event_t *event = scratch.lookup(&key);
    if (!event)
        return 0;
    event->kind = EVENT_EXEC;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->size = 0;
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *enabled = tracked.lookup(&pid);
    if (!enabled || (args->fd != 1 && args->fd != 2))
        return 0;
    u32 key = 0;
    struct event_t *event = scratch.lookup(&key);
    if (!event)
        return 0;
    event->kind = EVENT_WRITE;
    event->pid = pid;
    event->fd = args->fd;
    event->size = args->count > CHUNK_SIZE ? CHUNK_SIZE : args->count;
    bpf_probe_read_user(&event->data, event->size, (void *)args->buf);
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *enabled = tracked.lookup(&pid);
    if (!enabled)
        return 0;
    u32 key = 0;
    struct event_t *event = scratch.lookup(&key);
    if (!event)
        return 0;
    event->kind = EVENT_EXIT;
    event->pid = pid;
    event->exit_code = args->exit_code;
    event->size = 0;
    events.perf_submit(args, event, sizeof(*event));
    tracked.delete(&pid);
    return 0;
}
"""


class Event(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("fd", ctypes.c_int32),
        ("exit_code", ctypes.c_int32),
        ("size", ctypes.c_uint32),
        ("data", ctypes.c_char * 4096),
    ]


class Observer:
    def __init__(self):
        state = Path(os.environ.get(
            "OSCP_WORKSPACE_STATE", Path.home() / ".local/state/oscp-workspace"))
        self.inbox = state / "passive-inbox"
        self.inbox.mkdir(parents=True, exist_ok=True)
        os.chmod(self.inbox, 0o700)
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.bpf = BPF(text=BPF_SOURCE)
        self.activities: dict[int, dict] = {}
        self.running = True
        self.last_sync = 0.0

    @staticmethod
    def _proc(pid: int, name: str) -> Path:
        return Path("/proc") / str(pid) / name

    def _start_ticks(self, pid: int) -> str:
        tail = self._proc(pid, "stat").read_text().rpartition(") ")[2].split()
        return tail[19]

    def _handle_exec(self, pid: int, uid: int) -> None:
        try:
            argv = [part.decode(errors="replace") for part in
                    self._proc(pid, "cmdline").read_bytes().split(b"\0") if part]
            if not argv or Path(argv[0]).name != "nmap":
                return
            process_key = f"{self.boot_id}:{pid}:{self._start_ticks(pid)}"
            stem = hashlib.sha256(process_key.encode()).hexdigest()
            output_path = self.inbox / f"{stem}.out"
            fd = os.open(output_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            tty = ""
            try:
                tty = os.readlink(self._proc(pid, "fd/1"))
            except OSError:
                pass
            status = self._proc(pid, "status").read_text()
            ppid = next((int(line.split()[1]) for line in status.splitlines()
                         if line.startswith("PPid:")), None)
            self.activities[pid] = {
                "process_key": process_key,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "argv": argv,
                "cwd": os.readlink(self._proc(pid, "cwd")),
                "tty": tty,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "output_file": output_path.name,
                "output_fd": fd,
                "size": output_path.stat().st_size,
            }
            self.bpf["tracked"][ctypes.c_uint(pid)] = ctypes.c_ubyte(1)
        except (FileNotFoundError, OSError, ValueError):
            return

    def _handle_write(self, event: Event) -> None:
        activity = self.activities.get(event.pid)
        if not activity:
            return
        # ponytail: cap raw output at 20 MiB; add rotation if one scan needs more.
        remaining = 20 * 1024 * 1024 - activity["size"]
        if remaining <= 0:
            return
        chunk = bytes(event.data[:min(event.size, remaining)])
        os.write(activity["output_fd"], chunk)
        activity["size"] += len(chunk)

    def _handle_exit(self, event: Event) -> None:
        activity = self.activities.pop(event.pid, None)
        if not activity:
            return
        os.close(activity.pop("output_fd"))
        activity.pop("size")
        raw = event.exit_code
        activity["exit_code"] = raw >> 8 if raw & 0x7f == 0 else 128 + (raw & 0x7f)
        activity["ended_at"] = datetime.now(timezone.utc).isoformat()
        stem = Path(activity["output_file"]).stem
        temporary = self.inbox / f".{stem}.json.tmp"
        final = self.inbox / f"{stem}.json"
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(activity, handle, ensure_ascii=False)
        os.chmod(temporary, 0o600)
        temporary.replace(final)
        self._sync()

    def _event(self, _cpu, data, _size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        if event.kind == 1:
            self._handle_exec(event.pid, event.uid)
        elif event.kind == 2:
            self._handle_write(event)
        elif event.kind == 3:
            self._handle_exit(event)

    @staticmethod
    def _lost(_cpu, count):
        print(f"ShadowTrace observer dropped {count} kernel events", file=sys.stderr)

    def _sync(self):
        try:
            request = urllib.request.Request(
                "http://127.0.0.1:8000/api/passive/sync", data=b"", method="POST")
            urllib.request.urlopen(request, timeout=1).read()
        except OSError:
            pass
        self.last_sync = time.monotonic()

    def stop(self, *_args):
        self.running = False

    def run(self):
        self.bpf["events"].open_perf_buffer(self._event, lost_cb=self._lost,
                                            page_cnt=64)
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        while self.running:
            self.bpf.perf_buffer_poll(timeout=500)
            if time.monotonic() - self.last_sync >= 2:
                self._sync()
        for activity in self.activities.values():
            os.close(activity["output_fd"])


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("passive observer must run as root")
    Observer().run()
