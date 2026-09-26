import importlib.util
import ctypes
import json
import os
from pathlib import Path


def load_observer():
    path = Path(__file__).parents[2] / "scripts" / "passive-observer.py"
    spec = importlib.util.spec_from_file_location("passive_observer", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


observer = load_observer()


def test_redact_argv_covers_separate_flags_headers_and_assignments():
    assert observer.redact_argv([
        "sshpass", "-p", "hunter2", "password=secret", "Authorization: Bearer abc",
        "https://john:secret@example.test/",
    ]) == [
        "sshpass", "-p", "<redacted>", "password=<redacted>",
        "Authorization: <redacted>", "https://<redacted>@example.test/",
    ]
    assert observer.redact_argv(["nmap", "-p", "80", "127.0.0.1"])[2] == "80"


def test_ffuf_exec_is_tracked_for_declared_output(tmp_path, monkeypatch):
    instance = observer.Observer.__new__(observer.Observer)
    instance.inbox = tmp_path
    instance.boot_id = "boot"
    instance.owner_uid = os.getuid()
    instance.owner_gid = os.getgid()
    instance.activities = {}
    monkeypatch.setattr(instance, "_argv", lambda _pid: [
        "/usr/bin/ffuf", "-u", "http://127.0.0.1/FUZZ",
        "-of", "json", "-o", "results.json"])
    monkeypatch.setattr(instance, "_start_ticks", lambda _pid: "123")
    monkeypatch.setattr(instance, "_context", lambda *_args: {
        "ppid": 1, "cwd": str(tmp_path), "fd_target": "/dev/pts/1"})

    instance._handle_activity_exec(77, instance.owner_uid)

    assert instance.activities[77]["argv"][0] == "/usr/bin/ffuf"
    assert instance.activities[77]["process_key"] == "boot:77:123"
    os.close(instance.activities[77]["output_fd"])


def test_curl_exec_is_tracked_for_declared_output(tmp_path, monkeypatch):
    instance = observer.Observer.__new__(observer.Observer)
    instance.inbox = tmp_path
    instance.boot_id = "boot"
    instance.owner_uid = os.getuid()
    instance.owner_gid = os.getgid()
    instance.activities = {}
    monkeypatch.setattr(instance, "_argv", lambda _pid: [
        "/usr/bin/curl", "-s", "-o", "body.html",
        "http://127.0.0.1:8000/docs"])
    monkeypatch.setattr(instance, "_start_ticks", lambda _pid: "124")
    monkeypatch.setattr(instance, "_context", lambda *_args: {
        "ppid": 1, "cwd": str(tmp_path), "fd_target": "/dev/pts/1"})

    instance._handle_activity_exec(78, instance.owner_uid)

    assert instance.activities[78]["argv"][0] == "/usr/bin/curl"
    assert instance.activities[78]["process_key"] == "boot:78:124"
    os.close(instance.activities[78]["output_fd"])


def test_event_spool_persists_sequence_and_loss(tmp_path):
    spool = observer.EventSpool(tmp_path, "boot")
    spool.mark_loss(7)
    spool.emit("process_exec", pid=42, uid=1000, payload={"argv": ["id"]})
    spool.flush()

    batches = [json.loads(path.read_text()) for path in tmp_path.glob("*.json")]
    assert len(batches) == 1
    events = batches[0]["events"]
    assert [event["sequence"] for event in events] == [1, 2]
    assert events[0]["kind"] == "loss"
    assert events[0]["loss_before"] == 7
    assert events[1]["event_key"].endswith(":2")


class Spool:
    def __init__(self):
        self.events = []

    def emit(self, kind, **values):
        self.events.append((kind, values))


def test_tty_input_is_redacted_when_echo_is_not_confirmed(monkeypatch):
    instance = observer.Observer.__new__(observer.Observer)
    instance.spool = Spool()
    monkeypatch.setattr(instance, "_context", lambda _pid, _fd: {
        "ppid": 1, "fd_target": "/dev/pts/2"})
    monkeypatch.setattr(instance, "_echo_enabled", lambda _pid: False)
    event = observer.Event(pid=10, tid=10, uid=1000, fd=0, ret=6,
                           size=6, total_size=6, timestamp_ns=5)
    event.data = b"secret"

    instance._generic_io(event, "stdio_read")

    kind, values = instance.spool.events[0]
    assert kind == "stdio_read"
    assert values["capture_state"] == "redacted"
    assert values["payload"]["redacted_bytes"] == 6
    assert "data_b64" not in values["payload"]


def test_output_truncation_is_explicit(monkeypatch):
    instance = observer.Observer.__new__(observer.Observer)
    instance.spool = Spool()
    monkeypatch.setattr(instance, "_context", lambda _pid, _fd: {"ppid": 1})
    event = observer.Event(pid=10, tid=10, uid=1000, fd=1, ret=5000,
                           size=4, total_size=5000, timestamp_ns=5)
    event.data = b"test"

    instance._generic_io(event, "stdio_write")

    _, values = instance.spool.events[0]
    assert values["capture_state"] == "partial"
    assert values["payload"]["truncated"] is True
    assert values["payload"]["original_size"] == 5000


def test_process_context_preserves_stdio_fd_topology(tmp_path, monkeypatch):
    process = tmp_path / "proc"
    (process / "fd").mkdir(parents=True)
    (process / "fd" / "0").symlink_to("/dev/pts/4")
    (process / "fd" / "1").symlink_to("pipe:[77]")
    (process / "fd" / "2").symlink_to("/tmp/error.log")
    instance = observer.Observer.__new__(observer.Observer)
    monkeypatch.setattr(instance, "_proc", lambda _pid, name: process / name)

    context = instance._context(42, include_stdio=True)

    assert context["fd_targets"] == {
        "0": "/dev/pts/4", "1": "pipe:[77]", "2": "/tmp/error.log"}


def test_server_pid_is_ignored_but_child_process_is_not(monkeypatch):
    instance = observer.Observer.__new__(observer.Observer)
    instance.ignored_pids = {10}
    seen = []
    monkeypatch.setattr(instance, "_generic_process", lambda event, kind: seen.append((event.pid, kind)))
    monkeypatch.setattr(instance, "_handle_activity_exec", lambda *_args: None)

    for pid in (10, 11):
        event = observer.Event(kind=1, pid=pid)
        instance._event(0, ctypes.byref(event), ctypes.sizeof(event))

    assert seen == [(11, "process_exec")]


def test_sync_is_requested_only_for_pending_batches(tmp_path):
    instance = observer.Observer.__new__(observer.Observer)
    instance.spool = observer.EventSpool(tmp_path / "events", "boot")
    instance.inbox = tmp_path / "legacy"
    instance.inbox.mkdir()
    assert instance._pending_sync() is False

    instance.spool.emit("process_exec", pid=42, payload={})
    instance.spool.flush()
    assert instance._pending_sync() is True


def test_bcc_loss_callback_records_dropped_events():
    instance = observer.Observer.__new__(observer.Observer)
    class LossSpool:
        def __init__(self):
            self.count = 0

        def mark_loss(self, count):
            self.count += count

    instance.spool = LossSpool()
    instance.activities = {1: {"loss_count": 2}}

    instance._lost(3)

    assert instance.spool.count == 3
    assert instance.activities[1]["loss_count"] == 5
