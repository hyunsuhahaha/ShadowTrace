import importlib.util
import json
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
