#!/usr/bin/env python3
"""Passively spool generic Kali endpoint events and preserve the Nmap MVP."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import signal
import socket
import sys
import termios
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from bcc import BPF
except ImportError:
    raise SystemExit("python3-bpfcc is required for passive capture")

MAX_DATA = 4096
MAX_PATH = 512
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>(?:password|passwd|pass|token|secret|cookie))=(?P<value>[^,]+)")
SECRET_FLAGS = {"--password", "--passwd", "--token", "--secret", "--cookie"}
SHORT_PASSWORD_TOOLS = {"sshpass", "nxc", "netexec", "hydra", "medusa"}
URL_SECRET = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)([^/@\s:]+):([^/@\s]+)@")

BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

#define OWNER_UID __OWNER_UID__
#define EVENT_EXEC 1
#define EVENT_WRITE 2
#define EVENT_EXIT 3
#define EVENT_FORK 4
#define EVENT_READ 5
#define EVENT_SOCKET 6
#define EVENT_FILESYSTEM 7
#define OP_CONNECT 1
#define OP_BIND 2
#define OP_LISTEN 3
#define OP_ACCEPT 4
#define OP_SENDTO 5
#define OP_OPENAT 10
#define OP_UNLINKAT 11
#define OP_MKDIRAT 12
#define OP_RENAMEAT2 13
#define MAX_DATA 4096
#define MAX_PATH 512
#define HEADER_BYTES __builtin_offsetof(struct event_t, data)

struct event_t {
    u32 kind;
    u32 op;
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    u32 gid;
    s32 fd;
    s32 ret;
    u32 size;
    u32 total_size;
    u32 flags;
    u32 family;
    u32 port;
    u64 timestamp_ns;
    unsigned char addr[16];
    char data[MAX_DATA];
    char data2[MAX_PATH];
};

struct io_args_t { s32 fd; const char *buf; };
struct socket_args_t { u32 op; s32 fd; u32 flags; const void *addr; };
struct path_args_t {
    u32 op;
    s32 fd;
    u32 flags;
    const char *path;
    const char *path2;
};

BPF_HASH(tracked, u32, u8);
BPF_HASH(reads, u32, struct io_args_t);
BPF_HASH(writes, u32, struct io_args_t);
BPF_HASH(sockets, u32, struct socket_args_t);
BPF_HASH(paths, u32, struct path_args_t);
BPF_LRU_HASH(sent_sockets, u64, u8, 16384);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);
BPF_PERF_OUTPUT(events);

static struct event_t *fresh_event() {
    u32 key = 0;
    struct event_t *event = scratch.lookup(&key);
    if (event) {
        __builtin_memset(event, 0, HEADER_BYTES);
        event->data[0] = 0;
        event->data2[0] = 0;
    }
    return event;
}

static int enabled(u32 pid) {
    return tracked.lookup(&pid) != 0;
}

static void fill_identity(struct event_t *event) {
    u64 id = bpf_get_current_pid_tgid();
    u64 ug = bpf_get_current_uid_gid();
    event->pid = id >> 32;
    event->tid = (u32)id;
    event->uid = (u32)ug;
    event->gid = ug >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent = args->parent_pid;
    u32 child = args->child_pid;
    u64 ug = bpf_get_current_uid_gid();
    if (!enabled(parent) && (u32)ug != OWNER_UID)
        return 0;
    u8 one = 1;
    tracked.update(&parent, &one);
    tracked.update(&child, &one);
    struct event_t *event = fresh_event();
    if (!event)
        return 0;
    event->kind = EVENT_FORK;
    event->pid = child;
    event->tid = child;
    event->ppid = parent;
    event->uid = (u32)ug;
    event->gid = ug >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    events.perf_submit(args, event, HEADER_BYTES);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 uid = (u32)bpf_get_current_uid_gid();
    if (!enabled(pid) && uid != OWNER_UID)
        return 0;
    u8 one = 1;
    tracked.update(&pid, &one);
    struct event_t *event = fresh_event();
    if (!event)
        return 0;
    event->kind = EVENT_EXEC;
    fill_identity(event);
    events.perf_submit(args, event, HEADER_BYTES);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    if (pid != tid || !enabled(pid))
        return 0;
    struct event_t *event = fresh_event();
    if (!event)
        return 0;
    event->kind = EVENT_EXIT;
    event->ret = args->exit_code;
    fill_identity(event);
    events.perf_submit(args, event, HEADER_BYTES);
    tracked.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    if (!enabled(pid) || args->fd != 0)
        return 0;
    struct io_args_t pending = {.fd = args->fd, .buf = (const char *)args->buf};
    reads.update(&tid, &pending);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct io_args_t *pending = reads.lookup(&tid);
    if (!pending)
        return 0;
    if (args->ret > 0) {
        struct event_t *event = fresh_event();
        if (event) {
            event->kind = EVENT_READ;
            event->fd = pending->fd;
            event->ret = args->ret;
            event->total_size = args->ret;
            event->size = args->ret > MAX_DATA ? MAX_DATA : args->ret;
            fill_identity(event);
            bpf_probe_read_user(event->data, event->size, pending->buf);
            events.perf_submit(args, event, HEADER_BYTES + event->size);
        }
    }
    reads.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    if (!enabled(pid) || (args->fd != 1 && args->fd != 2))
        return 0;
    struct io_args_t pending = {.fd = args->fd, .buf = (const char *)args->buf};
    writes.update(&tid, &pending);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct io_args_t *pending = writes.lookup(&tid);
    if (!pending)
        return 0;
    if (args->ret > 0) {
        struct event_t *event = fresh_event();
        if (event) {
            event->kind = EVENT_WRITE;
            event->fd = pending->fd;
            event->ret = args->ret;
            event->total_size = args->ret;
            event->size = args->ret > MAX_DATA ? MAX_DATA : args->ret;
            fill_identity(event);
            bpf_probe_read_user(event->data, event->size, pending->buf);
            events.perf_submit(args, event, HEADER_BYTES + event->size);
        }
    }
    writes.delete(&tid);
    return 0;
}

static int enter_socket(u32 tid, u32 op, s32 fd, const void *addr, u32 flags) {
    struct socket_args_t pending = {.op = op, .fd = fd, .flags = flags, .addr = addr};
    sockets.update(&tid, &pending);
    return 0;
}

static int exit_socket(void *ctx, s64 ret) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    struct socket_args_t *pending = sockets.lookup(&tid);
    if (!pending)
        return 0;
    struct event_t *event = fresh_event();
    if (event) {
        event->kind = EVENT_SOCKET;
        event->op = pending->op;
        event->fd = pending->fd;
        event->flags = pending->flags;
        event->ret = ret;
        fill_identity(event);
        if (pending->addr) {
            u16 family = 0;
            bpf_probe_read_user(&family, sizeof(family), pending->addr);
            event->family = family;
            if (family == AF_INET) {
                struct sockaddr_in address = {};
                bpf_probe_read_user(&address, sizeof(address), pending->addr);
                event->port = address.sin_port;
                __builtin_memcpy(event->addr, &address.sin_addr.s_addr, 4);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 address6 = {};
                bpf_probe_read_user(&address6, sizeof(address6), pending->addr);
                event->port = address6.sin6_port;
                __builtin_memcpy(event->addr, &address6.sin6_addr, 16);
            }
        }
        events.perf_submit(ctx, event, HEADER_BYTES);
    }
    sockets.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_socket((u32)id, OP_CONNECT, args->fd, (void *)args->uservaddr, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_connect) { return exit_socket(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_socket((u32)id, OP_BIND, args->fd, (void *)args->umyaddr, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_bind) { return exit_socket(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_listen) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_socket((u32)id, OP_LISTEN, args->fd, 0, args->backlog);
}
TRACEPOINT_PROBE(syscalls, sys_exit_listen) { return exit_socket(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_socket((u32)id, OP_ACCEPT, args->fd,
                        (void *)args->upeer_sockaddr, args->flags);
}
TRACEPOINT_PROBE(syscalls, sys_exit_accept4) { return exit_socket(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32) || !args->addr) return 0;
    u64 key = (id & 0xffffffff00000000ULL) | (u32)args->fd;
    if (sent_sockets.lookup(&key)) return 0;
    u8 one = 1;
    sent_sockets.update(&key, &one);
    return enter_socket((u32)id, OP_SENDTO, args->fd, (void *)args->addr, args->flags);
}
TRACEPOINT_PROBE(syscalls, sys_exit_sendto) { return exit_socket(args, args->ret); }

static int enter_path(u32 tid, u32 op, s32 fd, u32 flags,
                      const char *path, const char *path2) {
    struct path_args_t pending = {
        .op = op, .fd = fd, .flags = flags, .path = path, .path2 = path2};
    paths.update(&tid, &pending);
    return 0;
}

static int exit_path(void *ctx, s64 ret) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct path_args_t *pending = paths.lookup(&tid);
    if (!pending)
        return 0;
    struct event_t *event = fresh_event();
    if (event) {
        event->kind = EVENT_FILESYSTEM;
        event->op = pending->op;
        event->fd = pending->fd;
        event->flags = pending->flags;
        event->ret = ret;
        fill_identity(event);
        if (pending->path) {
            int path_size = bpf_probe_read_user_str(event->data, MAX_PATH, pending->path);
            event->size = path_size > 0 ? path_size : 0;
        }
        if (pending->path2)
            bpf_probe_read_user_str(event->data2, MAX_PATH, pending->path2);
        events.perf_submit(ctx, event, sizeof(*event));
    }
    paths.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    if ((args->flags & 3) == 0 && !(args->flags & (64 | 512 | 1024))) return 0;
    return enter_path((u32)id, OP_OPENAT, args->dfd, args->flags,
                      (const char *)args->filename, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_openat) { return exit_path(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_path((u32)id, OP_UNLINKAT, args->dfd, args->flag,
                      (const char *)args->pathname, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) { return exit_path(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_path((u32)id, OP_MKDIRAT, args->dfd, args->mode,
                      (const char *)args->pathname, 0);
}
TRACEPOINT_PROBE(syscalls, sys_exit_mkdirat) { return exit_path(args, args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    u64 id = bpf_get_current_pid_tgid();
    if (!enabled(id >> 32)) return 0;
    return enter_path((u32)id, OP_RENAMEAT2, args->olddfd, args->flags,
                      (const char *)args->oldname, (const char *)args->newname);
}
TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) { return exit_path(args, args->ret); }
"""


class Event(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint32), ("op", ctypes.c_uint32),
        ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32), ("fd", ctypes.c_int32),
        ("ret", ctypes.c_int32), ("size", ctypes.c_uint32),
        ("total_size", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("family", ctypes.c_uint32), ("port", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("addr", ctypes.c_ubyte * 16),
        ("data", ctypes.c_char * MAX_DATA),
        ("data2", ctypes.c_char * MAX_PATH),
    ]


def redact_argv(argv: list[str]) -> list[str]:
    redacted = []
    hide_next = False
    short_password = bool(argv and Path(argv[0]).name in SHORT_PASSWORD_TOOLS)
    for value in argv:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        lowered = value.lower()
        if value in SECRET_FLAGS or (short_password and value == "-p"):
            redacted.append(value)
            hide_next = True
            continue
        if lowered.startswith(("authorization:", "cookie:")):
            redacted.append(value.split(":", 1)[0] + ": <redacted>")
            continue
        value = SECRET_ASSIGNMENT.sub(
            lambda match: f"{match.group('key')}=<redacted>", value)
        redacted.append(URL_SECRET.sub(r"\1<redacted>@", value))
    return redacted


class EventSpool:
    def __init__(self, directory: Path, boot_id: str):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.boot_id = boot_id
        self.observer_id = uuid.uuid4().hex[:16]
        self.sequence = 0
        self.pending_loss = 0
        self.events: list[dict] = []

    def mark_loss(self, count: int) -> None:
        self.pending_loss += count
        self.emit("loss", payload={"dropped_events": count},
                  capture_state="lost", confidence=0)

    def emit(self, kind: str, *, payload: dict, monotonic_ns: int = 0,
             pid: int | None = None, tid: int | None = None,
             ppid: int | None = None, uid: int | None = None,
             capture_state: str = "captured", confidence: int = 100,
             sensitive: bool = False) -> None:
        self.sequence += 1
        loss_before, self.pending_loss = self.pending_loss, 0
        self.events.append({
            "event_key": f"{self.boot_id}:{self.observer_id}:{self.sequence}",
            "sequence": self.sequence,
            "kind": kind,
            "source": "ebpf",
            "monotonic_ns": monotonic_ns,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "pid": pid,
            "tid": tid,
            "ppid": ppid,
            "uid": uid,
            "payload": payload,
            "capture_state": capture_state,
            "confidence": confidence,
            "loss_before": loss_before,
            "sensitive": sensitive,
        })
        if len(self.events) >= 128:
            self.flush()

    def flush(self) -> None:
        if not self.events:
            return
        first, last = self.events[0]["sequence"], self.events[-1]["sequence"]
        name = f"{self.observer_id}-{first:020d}-{last:020d}.json"
        temporary = self.directory / f".{name}.tmp"
        final = self.directory / name
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump({"schema": 1, "observer_id": self.observer_id,
                       "boot_id": self.boot_id, "events": self.events},
                      handle, ensure_ascii=False, separators=(",", ":"))
        os.chmod(temporary, 0o600)
        temporary.replace(final)
        self.events = []


class Observer:
    def __init__(self):
        state = Path(os.environ.get(
            "OSCP_WORKSPACE_STATE", Path.home() / ".local/state/oscp-workspace"))
        self.inbox = state / "passive-inbox"
        self.inbox.mkdir(parents=True, exist_ok=True)
        os.chmod(self.inbox, 0o700)
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.owner_uid = int(os.environ.get("OSCP_WORKSPACE_OWNER_UID", os.getuid()))
        source = BPF_SOURCE.replace("__OWNER_UID__", str(self.owner_uid))
        self.bpf = BPF(text=source)
        self.spool = EventSpool(state / "passive-event-inbox", self.boot_id)
        self.activities: dict[int, dict] = {}
        self.running = True
        self.last_flush = self.last_sync = 0.0
        self._seed_existing_processes()

    @staticmethod
    def _proc(pid: int, name: str) -> Path:
        return Path("/proc") / str(pid) / name

    @staticmethod
    def _decode_path(raw: bytes) -> str:
        return raw.split(b"\0", 1)[0].decode(errors="replace")

    def _seed_existing_processes(self) -> None:
        one = ctypes.c_ubyte(1)
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / "status").read_text()
                uid_line = next(line for line in status.splitlines()
                                if line.startswith("Uid:"))
                if int(uid_line.split()[2]) == self.owner_uid:
                    self.bpf["tracked"][ctypes.c_uint(int(entry.name))] = one
            except (FileNotFoundError, OSError, StopIteration, ValueError):
                continue

    def _context(self, pid: int, fd: int | None = None) -> dict:
        context: dict = {}
        try:
            tail = self._proc(pid, "stat").read_text().rpartition(") ")[2].split()
            context.update(ppid=int(tail[1]), pgid=int(tail[2]), sid=int(tail[3]),
                           tty_nr=int(tail[4]), tpgid=int(tail[5]),
                           start_ticks=tail[19])
        except (FileNotFoundError, OSError, IndexError, ValueError):
            pass
        for name in ("cwd", "exe"):
            try:
                context[name] = os.readlink(self._proc(pid, name))
            except OSError:
                pass
        if fd is not None:
            try:
                context["fd_target"] = os.readlink(self._proc(pid, f"fd/{fd}"))
            except OSError:
                pass
        namespaces = {}
        for name in ("pid", "mnt", "net", "user"):
            try:
                namespaces[name] = os.readlink(self._proc(pid, f"ns/{name}"))
            except OSError:
                pass
        if namespaces:
            context["namespaces"] = namespaces
        try:
            context["cgroup"] = self._proc(pid, "cgroup").read_text().splitlines()
        except OSError:
            pass
        return context

    def _echo_enabled(self, pid: int) -> bool | None:
        try:
            fd = os.open(self._proc(pid, "fd/0"),
                         os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
            try:
                return bool(termios.tcgetattr(fd)[3] & termios.ECHO)
            finally:
                os.close(fd)
        except (OSError, termios.error):
            return None

    def _argv(self, pid: int) -> list[str]:
        return [part.decode(errors="replace") for part in
                self._proc(pid, "cmdline").read_bytes().split(b"\0") if part]

    def _generic_process(self, event: Event, kind: str) -> None:
        context = self._context(event.pid)
        payload = {"gid": event.gid, **context}
        if kind == "process_exec":
            try:
                argv = redact_argv(self._argv(event.pid))
                payload.update(argv=argv, executable=argv[0] if argv else "")
            except (FileNotFoundError, OSError):
                payload["argv_unavailable"] = True
        if kind == "process_exit":
            raw = event.ret
            payload["exit_code"] = (
                raw >> 8 if raw & 0x7f == 0 else 128 + (raw & 0x7f))
        self.spool.emit(kind, payload=payload, monotonic_ns=event.timestamp_ns,
                        pid=event.pid, tid=event.tid,
                        ppid=event.ppid or context.get("ppid"), uid=event.uid,
                        capture_state="partial" if payload.get("argv_unavailable") else "captured",
                        confidence=90 if payload.get("argv_unavailable") else 100)

    def _generic_io(self, event: Event, kind: str) -> None:
        context = self._context(event.pid, event.fd)
        truncated = event.total_size > event.size
        payload = {"fd": event.fd, "result": event.ret,
                   "original_size": event.total_size,
                   "captured_size": event.size, "truncated": truncated, **context}
        state, confidence, sensitive = ("partial", 80, True) if truncated \
            else ("captured", 100, True)
        if kind == "stdio_read":
            target = str(context.get("fd_target", ""))
            echo = self._echo_enabled(event.pid) if target.startswith("/dev/") else None
            payload["echo"] = echo
            if not target.startswith(("/dev/pts/", "/dev/tty")) or echo is not True:
                payload["redacted_bytes"] = event.size
                state, confidence = "redacted", 100
            else:
                payload["data_b64"] = base64.b64encode(
                    bytes(event.data[:event.size])).decode()
        else:
            payload["data_b64"] = base64.b64encode(
                bytes(event.data[:event.size])).decode()
        self.spool.emit(kind, payload=payload, monotonic_ns=event.timestamp_ns,
                        pid=event.pid, tid=event.tid, ppid=context.get("ppid"),
                        uid=event.uid, capture_state=state, confidence=confidence,
                        sensitive=sensitive)

    def _generic_socket(self, event: Event) -> None:
        operations = {1: "connect", 2: "bind", 3: "listen",
                      4: "accept", 5: "sendto"}
        context = self._context(event.pid, event.fd)
        payload = {"operation": operations.get(event.op, "unknown"),
                   "fd": event.fd, "result": event.ret,
                   "family": event.family, "flags": event.flags, **context}
        if event.op == 5:
            payload["sampling"] = "first-sendto-per-process-fd"
        try:
            if event.family == socket.AF_INET:
                payload["address"] = socket.inet_ntop(
                    socket.AF_INET, bytes(event.addr[:4]))
            elif event.family == socket.AF_INET6:
                payload["address"] = socket.inet_ntop(
                    socket.AF_INET6, bytes(event.addr))
            if event.port:
                payload["port"] = socket.ntohs(event.port)
        except OSError:
            payload["address_unavailable"] = True
        partial = bool(payload.get("address_unavailable")) or event.op == 5
        self.spool.emit("socket", payload=payload,
                        monotonic_ns=event.timestamp_ns, pid=event.pid,
                        tid=event.tid, ppid=context.get("ppid"), uid=event.uid,
                        capture_state="partial" if partial else "captured",
                        confidence=70 if event.op == 5 else (90 if partial else 100))

    def _generic_filesystem(self, event: Event) -> None:
        operations = {10: "openat", 11: "unlinkat", 12: "mkdirat", 13: "renameat2"}
        context = self._context(event.pid)
        size = min(max(event.size, 0), MAX_PATH)
        payload = {"operation": operations.get(event.op, "unknown"),
                   "dirfd": event.fd, "flags": event.flags,
                   "result": event.ret, "path": self._decode_path(bytes(event.data[:size])),
                   **context}
        second = self._decode_path(bytes(event.data2))
        if second:
            payload["path2"] = second
        self.spool.emit("filesystem", payload=payload,
                        monotonic_ns=event.timestamp_ns, pid=event.pid,
                        tid=event.tid, ppid=context.get("ppid"), uid=event.uid,
                        capture_state="partial" if size >= MAX_PATH else "captured",
                        confidence=85 if size >= MAX_PATH else 100)

    def _start_ticks(self, pid: int) -> str:
        tail = self._proc(pid, "stat").read_text().rpartition(") ")[2].split()
        return tail[19]

    def _handle_nmap_exec(self, pid: int, uid: int) -> None:
        try:
            argv = redact_argv(self._argv(pid))
            if not argv or Path(argv[0]).name != "nmap":
                return
            process_key = f"{self.boot_id}:{pid}:{self._start_ticks(pid)}"
            stem = hashlib.sha256(process_key.encode()).hexdigest()
            output_path = self.inbox / f"{stem}.out"
            fd = os.open(output_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            context = self._context(pid, 1)
            self.activities[pid] = {
                "process_key": process_key, "pid": pid,
                "ppid": context.get("ppid"), "uid": uid, "argv": argv,
                "cwd": context.get("cwd", ""), "tty": context.get("fd_target", ""),
                "started_at": datetime.now(timezone.utc).isoformat(),
                "output_file": output_path.name, "output_fd": fd,
                "size": output_path.stat().st_size, "capture_truncated": False,
                "loss_count": 0,
            }
        except (FileNotFoundError, OSError, ValueError):
            return

    def _handle_nmap_write(self, event: Event) -> None:
        activity = self.activities.get(event.pid)
        if not activity:
            return
        remaining = 20 * 1024 * 1024 - activity["size"]
        if remaining <= 0:
            activity["capture_truncated"] = True
            return
        chunk = bytes(event.data[:min(event.size, remaining)])
        os.write(activity["output_fd"], chunk)
        activity["size"] += len(chunk)
        if event.total_size > event.size or len(chunk) < event.size:
            activity["capture_truncated"] = True

    def _handle_nmap_exit(self, event: Event) -> None:
        activity = self.activities.pop(event.pid, None)
        if not activity:
            return
        os.close(activity.pop("output_fd"))
        activity.pop("size")
        raw = event.ret
        activity["exit_code"] = raw >> 8 if raw & 0x7f == 0 else 128 + (raw & 0x7f)
        activity["ended_at"] = datetime.now(timezone.utc).isoformat()
        stem = Path(activity["output_file"]).stem
        temporary = self.inbox / f".{stem}.json.tmp"
        final = self.inbox / f"{stem}.json"
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(activity, handle, ensure_ascii=False)
        os.chmod(temporary, 0o600)
        temporary.replace(final)
        self.spool.flush()
        self._sync()

    def _event(self, _cpu, data, _size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        if event.kind == 1:
            self._generic_process(event, "process_exec")
            self._handle_nmap_exec(event.pid, event.uid)
        elif event.kind == 2:
            self._generic_io(event, "stdio_write")
            self._handle_nmap_write(event)
        elif event.kind == 3:
            self._generic_process(event, "process_exit")
            self._handle_nmap_exit(event)
        elif event.kind == 4:
            self._generic_process(event, "process_fork")
        elif event.kind == 5:
            self._generic_io(event, "stdio_read")
        elif event.kind == 6:
            self._generic_socket(event)
        elif event.kind == 7:
            self._generic_filesystem(event)

    def _lost(self, _cpu, count):
        self.spool.mark_loss(count)
        for activity in self.activities.values():
            activity["loss_count"] += count
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
            self.bpf.perf_buffer_poll(timeout=250)
            now = time.monotonic()
            if now - self.last_flush >= 1:
                self.spool.flush()
                self.last_flush = now
            if now - self.last_sync >= 2:
                self._sync()
        self.spool.flush()
        for activity in self.activities.values():
            os.close(activity["output_fd"])


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("passive observer must run as root")
    Observer().run()
