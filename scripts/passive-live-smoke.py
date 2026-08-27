#!/usr/bin/env python3
"""Exercise live observer signals and verify their database-backed API rows."""
from __future__ import annotations

import argparse
import json
import os
import pty
import select
import shlex
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone


def request(base_url: str, path: str, method: str = "GET"):
    call = urllib.request.Request(base_url.rstrip("/") + path, method=method)
    with urllib.request.urlopen(call, timeout=10) as response:
        return json.load(response)


def local_listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_once():
        connection, _ = server.accept()
        connection.recv(16)
        connection.close()
        server.close()

    threading.Thread(target=accept_once, daemon=True).start()
    return port


def exercise(marker: str) -> int:
    port = local_listener()
    directory = f"/tmp/shadowtrace-smoke-{marker}"
    pid, master = pty.fork()
    if pid == 0:
        os.execv("/usr/bin/bash", ["bash", "--noprofile", "--norc"])
    commands = [
        f"printf {shlex.quote(marker + '\\n')}",
        f"mkdir {shlex.quote(directory)}",
        f"printf x > {shlex.quote(directory + '/before')}",
        f"mv {shlex.quote(directory + '/before')} {shlex.quote(directory + '/after')}",
        ("python3 -c " + shlex.quote(
            f"import socket;s=socket.create_connection(('127.0.0.1',{port}));"
            "s.sendall(b'x');s.close()")),
        "python3 -c " + shlex.quote("import os;os.write(1,b'A'*5000)"),
        f"rm -f {shlex.quote(directory + '/after')}",
        f"rmdir {shlex.quote(directory)}",
        "exit",
    ]
    os.write(master, ("\n".join(commands) + "\n").encode())
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.25)
        if ready:
            try:
                os.read(master, 8192)
            except OSError:
                break
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited:
            break
    else:
        os.kill(pid, 15)
        raise RuntimeError("PTY smoke shell did not exit within 20 seconds")
    os.close(master)
    return pid


def lineage(events: list[dict], root_pid: int) -> set[int]:
    result = {root_pid}
    changed = True
    while changed:
        changed = False
        for event in events:
            if event.get("ppid") in result and event.get("pid") not in result:
                result.add(event["pid"])
                changed = True
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    marker = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    try:
        root_pid = exercise(marker)
        time.sleep(2)
        sync = request(args.base_url, "/api/passive/sync", "POST")
        rows = request(args.base_url, "/api/passive/events?limit=500")
    except (OSError, RuntimeError, urllib.error.URLError) as exc:
        raise SystemExit(f"live smoke failed: {exc}")
    recent = []
    for row in rows:
        recorded = datetime.fromisoformat(row["recorded_at"].replace("Z", "+00:00"))
        if recorded.tzinfo is None:
            recorded = recorded.replace(tzinfo=timezone.utc)
        if recorded >= started:
            recent.append(row)
    pids = lineage(recent, root_pid)
    captured = [row for row in recent if row.get("pid") in pids]
    kinds = {row["kind"] for row in captured}
    socket_connect = any(
        row["kind"] == "socket" and json.loads(row["payload"]).get("operation") == "connect"
        for row in captured)
    truncated = any(
        row["kind"] == "stdio_write" and row["capture_state"] == "partial"
        and json.loads(row["payload"]).get("truncated") is True for row in captured)
    required = {"process_fork", "process_exec", "process_exit",
                "stdio_read", "stdio_write", "filesystem"}
    missing = sorted(required - kinds)
    if not socket_connect:
        missing.append("socket:connect")
    if not truncated:
        missing.append("stdio_write:truncated")
    result = {"marker": marker, "root_pid": root_pid, "lineage_pids": sorted(pids),
              "events": len(captured), "kinds": sorted(kinds), "sync": sync,
              "missing": missing}
    print(json.dumps(result, indent=2))
    if missing:
        raise SystemExit("live smoke incomplete: " + ", ".join(missing))


if __name__ == "__main__":
    main()
