import base64
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (
    CommandActivity, GraphNode, ProcessInstance, RawActivityEvent,
    RemoteSessionCandidate, TerminalSession,
)
from app.modules.passive_activity.reconstruction import reconstruct


BASE = datetime(2026, 8, 27, 12, tzinfo=timezone.utc)


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def assert_evidence_without_graph_claim(db):
    assert db.query(RawActivityEvent).count() > 0
    assert db.query(GraphNode).count() == 0


class Events:
    def __init__(self, db):
        self.db = db
        self.sequence = {}
        self.offset = 0

    def add(self, kind, pid=None, *, payload=None, observer="observer-a",
            sequence=None, state="captured", confidence=100, loss_before=0,
            boot="boot-a", ppid=None):
        if sequence is None:
            sequence = self.sequence.get(observer, 0) + 1
        self.sequence[observer] = sequence
        self.offset += 1
        row = RawActivityEvent(
            event_key=f"{boot}:{observer}:{sequence}", observer_id=observer,
            boot_id=boot, sequence=sequence, kind=kind, source="test",
            monotonic_ns=self.offset * 1_000_000,
            recorded_at=BASE + timedelta(milliseconds=self.offset * 100),
            pid=pid, tid=pid, ppid=ppid, uid=1000,
            payload=json.dumps(payload or {}), capture_state=state,
            confidence=confidence, loss_before=loss_before, sensitive=False,
        )
        self.db.add(row)
        self.db.flush()
        return row

    def process(self, pid, argv, *, ppid=100, sid=100, pgid=None, tpgid=None,
                tty_nr=1, tty="/dev/pts/1", fds=None, observer="observer-a",
                start=None, exit=True):
        start = start or str(pid * 10)
        pgid = pgid or pid
        tpgid = pgid if tpgid is None else tpgid
        context = {
            "start_ticks": start, "sid": sid, "pgid": pgid, "tpgid": tpgid,
            "tty_nr": tty_nr, "cwd": "/tmp", "executable": argv[0],
            "argv": argv, "fd_targets": fds or {"0": tty, "1": tty, "2": tty},
            "namespaces": {"pid": "pid:[1]", "mnt": "mnt:[1]",
                           "net": "net:[1]", "user": "user:[1]"},
            "cgroup": ["0::/user.slice"],
        }
        self.add("process_exec", pid, payload=context, ppid=ppid, observer=observer)
        if exit:
            self.add("process_exit", pid, payload={**context, "exit_code": 0},
                     ppid=ppid, observer=observer)
        return context

    def input(self, pid, text, context, *, observer="observer-a"):
        return self.add("stdio_read", pid, observer=observer, payload={
            **context, "fd": 0, "fd_target": context["fd_targets"]["0"],
            "data_b64": base64.b64encode(text.encode()).decode(),
            "captured_size": len(text), "original_size": len(text),
        })

    def output(self, pid, text, context, *, fd=1, observer="observer-a"):
        return self.add("stdio_write", pid, observer=observer, payload={
            **context, "fd": fd, "fd_target": context["fd_targets"][str(fd)],
            "data_b64": base64.b64encode(text.encode()).decode(),
            "captured_size": len(text), "original_size": len(text),
        })


def shell(events, pid=100, *, tty_nr=1, tty="/dev/pts/1", observer="observer-a"):
    return events.process(pid, ["/usr/bin/bash"], ppid=1, sid=pid, pgid=pid,
                          tpgid=pid, tty_nr=tty_nr, tty=tty, observer=observer,
                          exit=False)


def test_plain_bash_command_and_shell_builtin_are_distinct_candidates():
    db = database(); events = Events(db)
    shell_context = shell(events)
    events.input(100, "cd /tmp\n", shell_context)
    events.input(100, "id\n", shell_context)
    events.process(101, ["/usr/bin/id"], ppid=100, sid=100, pgid=101,
                   tty_nr=1, tty="/dev/pts/1")
    db.commit()

    assert reconstruct(db) == {
        "processes": 2, "sessions": 1, "commands": 2, "remote_candidates": 0}
    rows = {row.command: row for row in db.query(CommandActivity)}
    assert rows["cd /tmp"].kind == "shell-input"
    assert rows["cd /tmp"].confidence == 55
    assert json.loads(rows["cd /tmp"].inference)["execution"] == "unconfirmed"
    assert rows["id"].kind == "command"
    assert rows["id"].confidence == 85
    assert rows["id"].loss_state == "complete"
    assert_evidence_without_graph_claim(db)


def test_pipeline_keeps_processes_and_stdio_topology():
    db = database(); events = Events(db)
    shell_context = shell(events)
    events.input(100, "nmap 127.0.0.1 | tee out.txt\n", shell_context)
    events.process(201, ["/usr/bin/nmap", "127.0.0.1"], ppid=100, sid=100,
                   pgid=201, fds={"0": "/dev/pts/1", "1": "pipe:[77]", "2": "/dev/pts/1"})
    events.process(202, ["/usr/bin/tee", "out.txt"], ppid=100, sid=100,
                   pgid=201, fds={"0": "pipe:[77]", "1": "/dev/pts/1", "2": "/dev/pts/1"})
    db.commit(); reconstruct(db)

    row = db.query(CommandActivity).filter_by(is_pipeline=True).one()
    assert row.command == "nmap 127.0.0.1 | tee out.txt"
    assert len(json.loads(row.process_instance_ids)) == 2
    assert json.loads(row.inference)["pipeline"] == "shared-pipe-fd+pgid"
    assert (row.confidence, row.loss_state) == (85, "complete")
    assert_evidence_without_graph_claim(db)


def test_redirect_is_fd_evidence_not_shell_semantics():
    db = database(); events = Events(db)
    shell_context = shell(events)
    events.input(100, "printf hi > out.txt\n", shell_context)
    events.process(203, ["/usr/bin/printf", "hi"], ppid=100, sid=100, pgid=203,
                   fds={"0": "/dev/pts/1", "1": "/tmp/out.txt", "2": "/dev/pts/1"})
    db.commit(); reconstruct(db)

    row = db.query(CommandActivity).filter_by(pgid=203).one()
    assert row.stdout_target == "/tmp/out.txt"
    assert json.loads(row.inference)["redirect"] == "stdout-fd-target"
    assert (row.confidence, row.loss_state) == (85, "complete")
    assert_evidence_without_graph_claim(db)


def test_background_job_uses_pgid_and_foreground_pgid():
    db = database(); events = Events(db)
    shell(events)
    events.process(204, ["/usr/bin/sleep", "1"], ppid=100, sid=100, pgid=204,
                   tpgid=100, tty_nr=1, tty="/dev/pts/1")
    db.commit(); reconstruct(db)

    row = db.query(CommandActivity).filter_by(pgid=204).one()
    assert row.is_background is True
    assert row.confidence == 95
    assert row.loss_state == "complete"
    assert_evidence_without_graph_claim(db)


def test_two_terminals_do_not_merge():
    db = database(); events = Events(db)
    shell(events, 100, tty_nr=1, tty="/dev/pts/1")
    shell(events, 200, tty_nr=2, tty="/dev/pts/2")
    events.process(101, ["/usr/bin/id"], ppid=100, sid=100, pgid=101,
                   tty_nr=1, tty="/dev/pts/1")
    events.process(201, ["/usr/bin/whoami"], ppid=200, sid=200, pgid=201,
                   tty_nr=2, tty="/dev/pts/2")
    db.commit(); reconstruct(db)

    assert db.query(TerminalSession).count() == 2
    assert {row.tty for row in db.query(TerminalSession)} == {"/dev/pts/1", "/dev/pts/2"}
    assert all(row.confidence == 100 and row.loss_state == "complete"
               for row in db.query(TerminalSession))
    assert_evidence_without_graph_claim(db)


def test_tmux_two_panes_are_separate_minimal_topologies():
    db = database(); events = Events(db)
    events.process(300, ["/usr/bin/tmux", "new-session"], ppid=1, sid=300,
                   pgid=300, tty_nr=1, tty="/dev/pts/1", exit=False)
    events.process(301, ["/usr/bin/bash"], ppid=300, sid=301, pgid=301,
                   tty_nr=2, tty="/dev/pts/2", exit=False)
    events.process(302, ["/usr/bin/bash"], ppid=300, sid=302, pgid=302,
                   tty_nr=3, tty="/dev/pts/3", exit=False)
    db.commit(); reconstruct(db)

    panes = db.query(TerminalSession).filter_by(kind="tmux-pane").all()
    assert {row.tty for row in panes} == {"/dev/pts/2", "/dev/pts/3"}
    assert panes[0].id != panes[1].id
    assert all(row.confidence == 100 and row.loss_state == "complete" for row in panes)
    assert_evidence_without_graph_claim(db)


def test_interactive_ssh_creates_remote_candidate_and_pty_evidence():
    db = database(); events = Events(db)
    shell(events)
    context = events.process(400, ["/usr/bin/ssh", "-p", "22", "-l", "kali", "target"], ppid=100,
                             sid=100, pgid=400, tty_nr=1, tty="/dev/pts/1", exit=False)
    events.input(400, "whoami\nsudo -l\n", context)
    events.output(400, "kali\n", context, fd=1)
    events.output(400, "sudo: password required\n", context, fd=2)
    db.commit(); reconstruct(db)

    remote = db.query(RemoteSessionCandidate).one()
    assert (remote.username, remote.destination, remote.confidence) == ("kali", "target", 70)
    inputs = db.query(CommandActivity).filter_by(kind="remote-input").all()
    assert {row.command for row in inputs} == {"whoami", "sudo -l"}
    assert all(row.confidence == 50 for row in inputs)
    assert all(json.loads(row.inference)["execution"] == "unconfirmed" for row in inputs)
    assert all(row.loss_state == "complete" for row in inputs)
    client = db.query(CommandActivity).filter_by(kind="command").one()
    assert set(json.loads(client.evidence_streams)) >= {"process", "stdin", "stdout", "stderr"}
    assert_evidence_without_graph_claim(db)


def test_local_sudo_l_is_correlated_but_not_semantically_promoted():
    db = database(); events = Events(db)
    shell_context = shell(events)
    events.input(100, "sudo -l\n", shell_context)
    events.process(500, ["/usr/bin/sudo", "-l"], ppid=100, sid=100, pgid=500,
                   tty_nr=1, tty="/dev/pts/1")
    db.commit(); reconstruct(db)

    row = db.query(CommandActivity).filter_by(command="sudo -l").one()
    assert row.kind == "command"
    assert row.confidence == 85
    assert row.loss_state == "complete"
    assert_evidence_without_graph_claim(db)


def test_short_lived_process_survives_missing_proc_context():
    db = database(); events = Events(db)
    shell(events)
    events.add("process_fork", 601, ppid=100, payload={
        "sid": 100, "pgid": 601, "tpgid": 601, "tty_nr": 1,
        "fd_targets": {"0": "/dev/pts/1", "1": "/dev/pts/1", "2": "/dev/pts/1"},
    })
    events.add("process_exit", 601, ppid=100, payload={"exit_code": 0})
    db.commit(); reconstruct(db)

    row = db.query(ProcessInstance).filter_by(pid=601).one()
    assert row.start_ticks == ""
    assert row.confidence == 80
    assert row.loss_state == "complete"
    assert json.loads(row.evidence_event_ids)
    assert_evidence_without_graph_claim(db)


def test_late_start_ticks_merge_the_same_pid_incarnation():
    db = database(); events = Events(db)
    shell(events)
    events.add("process_fork", 602, ppid=100, payload={
        "sid": 100, "pgid": 602, "tpgid": 602, "tty_nr": 1,
        "fd_targets": {"0": "/dev/pts/1", "1": "/dev/pts/1", "2": "/dev/pts/1"},
    })
    events.process(602, ["/usr/bin/true"], ppid=100, sid=100, pgid=602,
                   tty_nr=1, tty="/dev/pts/1", start="6020")
    db.commit(); reconstruct(db)

    rows = db.query(ProcessInstance).filter_by(pid=602).all()
    assert len(rows) == 1
    assert rows[0].start_ticks == "6020"
    assert rows[0].confidence == 100
    assert_evidence_without_graph_claim(db)


def test_late_exec_replaces_stale_input_only_candidate():
    db = database(); events = Events(db)
    context = shell(events)
    events.input(100, "id\n", context)
    db.commit(); reconstruct(db)
    assert db.query(CommandActivity).one().kind == "shell-input"

    events.process(101, ["/usr/bin/id"], ppid=100, sid=100, pgid=101,
                   tty_nr=1, tty="/dev/pts/1")
    db.commit(); reconstruct(db)

    rows = db.query(CommandActivity).all()
    assert len(rows) == 1
    assert (rows[0].kind, rows[0].command, rows[0].confidence) == ("command", "id", 85)
    assert_evidence_without_graph_claim(db)


def test_observer_restart_keeps_session_and_marks_coverage_gap():
    db = database(); events = Events(db)
    context = shell(events, observer="observer-a")
    events.input(100, "cd /tmp\n", context, observer="observer-b")
    db.commit(); reconstruct(db)

    session = db.query(TerminalSession).one()
    assert "observer-restart" in session.loss_state
    assert json.loads(session.observer_ids) == ["observer-a", "observer-b"]
    assert session.confidence == 85
    assert_evidence_without_graph_claim(db)


def test_event_loss_sequence_gap_and_truncation_reduce_claims_idempotently():
    db = database(); events = Events(db)
    context = {
        "start_ticks": "1000", "sid": 100, "pgid": 100, "tpgid": 100,
        "tty_nr": 1, "cwd": "/tmp", "executable": "/usr/bin/bash",
        "argv": ["/usr/bin/bash"],
        "fd_targets": {"0": "/dev/pts/1", "1": "/dev/pts/1", "2": "/dev/pts/1"},
    }
    events.add("process_exec", 100, payload=context, ppid=1, sequence=1)
    events.add("stdio_write", 100, payload={**context, "fd": 1,
               "fd_target": "/dev/pts/1", "truncated": True}, sequence=3,
               state="partial", confidence=80)
    events.add("loss", payload={"dropped_events": 7}, sequence=4,
               state="lost", confidence=0, loss_before=7)
    db.commit()

    first = reconstruct(db)
    second = reconstruct(db)
    assert first == second
    assert db.query(ProcessInstance).count() == 1
    process = db.query(ProcessInstance).one()
    assert {"event-loss", "partial-capture", "sequence-gap"} <= set(
        process.loss_state.split(","))
    assert process.confidence == 80
    assert_evidence_without_graph_claim(db)
