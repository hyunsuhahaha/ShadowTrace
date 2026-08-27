from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ...models import (
    CommandActivity, ProcessInstance, RawActivityEvent, RemoteSessionCandidate,
    TerminalSession,
)

SHELLS = {"bash", "dash", "fish", "ksh", "sh", "zsh"}
SSH_NAMES = {"ssh"}


def _json(value, default):
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, type(default)) else default
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _losses(events: list[RawActivityEvent]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    previous: dict[str, int] = {}
    for event in sorted(events, key=lambda item: (item.observer_id, item.sequence)):
        before = previous.get(event.observer_id)
        if before is not None and event.sequence != before + 1:
            result[event.observer_id].add("sequence-gap")
        previous[event.observer_id] = event.sequence
        if event.kind == "loss" or event.loss_before:
            result[event.observer_id].add("event-loss")
    return result


def _loss_state(values: set[str]) -> str:
    return ",".join(sorted(values)) if values else "complete"


def _basename(process: dict) -> str:
    return Path(process.get("executable") or "").name


def _terminal_identity(process: dict) -> tuple[str, str] | None:
    tty_nr = process.get("tty_nr") or 0
    tty = process.get("tty") or ""
    sid = process.get("sid")
    if not tty_nr and not tty.startswith("/dev/"):
        return None
    token = str(tty_nr) if tty_nr else tty
    identity = ":".join((process["boot_id"], process.get("pid_namespace", ""),
                         str(sid or 0), token))
    return identity, hashlib.sha256(identity.encode()).hexdigest()


def _processes(events: list[RawActivityEvent], observer_loss: dict[str, set[str]]):
    processes: dict[str, dict] = {}
    current: dict[tuple[str, int], str] = {}
    event_process: dict[int, str] = {}
    for event in sorted(events, key=lambda item: (item.recorded_at, item.monotonic_ns, item.id)):
        if event.pid is None:
            continue
        payload = _json(event.payload, {})
        start_ticks = str(payload.get("start_ticks") or "")
        slot = (event.boot_id, event.pid)
        old_key = current.get(slot)
        key = (f"{event.boot_id}:{event.pid}:{start_ticks}" if start_ticks else
               old_key or f"{event.boot_id}:{event.pid}:event-{event.id}")
        if (start_ticks and old_key and old_key != key and old_key in processes
                and processes[old_key]["ended_at"] is None):
            process = processes.pop(old_key)
            process["process_key"] = key
            process["start_ticks"] = start_ticks
            processes[key] = process
            for event_id, process_key in list(event_process.items()):
                if process_key == old_key:
                    event_process[event_id] = key
        current[slot] = key
        event_process[event.id] = key
        process = processes.setdefault(key, {
            "process_key": key, "boot_id": event.boot_id, "pid": event.pid,
            "tgid": event.pid, "start_ticks": start_ticks, "ppid": event.ppid,
            "sid": None, "pgid": None, "tty_nr": None, "tpgid": None,
            "tty": "", "pid_namespace": "", "mount_namespace": "",
            "network_namespace": "", "user_namespace": "", "cgroup": [],
            "executable": "", "argv": [], "cwd": "", "fd_topology": {},
            "started_at": event.recorded_at, "ended_at": None, "exit_code": None,
            "confidence": 100, "losses": set(), "event_ids": [],
            "evidence_streams": defaultdict(list),
            "observer_ids": set(), "exec": False, "min_monotonic_ns": event.monotonic_ns,
        })
        process["event_ids"].append(event.id)
        stream = "process"
        if event.kind == "stdio_read":
            stream = "stdin"
        elif event.kind == "stdio_write":
            stream = "stderr" if payload.get("fd") == 2 else "stdout"
        elif event.kind in {"socket", "filesystem"}:
            stream = event.kind
        process["evidence_streams"][stream].append(event.id)
        process["observer_ids"].add(event.observer_id)
        process["losses"].update(observer_loss[event.observer_id])
        if event.capture_state == "partial":
            process["losses"].add("partial-capture")
        process["started_at"] = min(process["started_at"], event.recorded_at)
        process["min_monotonic_ns"] = min(process["min_monotonic_ns"], event.monotonic_ns)
        process["confidence"] = min(process["confidence"], event.confidence)
        if event.ppid is not None:
            process["ppid"] = event.ppid
        for name in ("sid", "pgid", "tty_nr", "tpgid"):
            if payload.get(name) is not None:
                process[name] = int(payload[name])
        for name in ("cwd", "executable"):
            if payload.get(name):
                process[name] = str(payload[name])
        namespaces = payload.get("namespaces") or {}
        for source, target in (("pid", "pid_namespace"), ("mnt", "mount_namespace"),
                               ("net", "network_namespace"), ("user", "user_namespace")):
            if namespaces.get(source):
                process[target] = str(namespaces[source])
        if payload.get("cgroup"):
            process["cgroup"] = payload["cgroup"]
        if payload.get("argv"):
            process["argv"] = [str(value) for value in payload["argv"]]
            process["executable"] = process["executable"] or process["argv"][0]
        targets = payload.get("fd_targets") or {}
        if isinstance(targets, dict):
            process["fd_topology"].update({str(k): str(v) for k, v in targets.items()})
        if payload.get("fd_target") and payload.get("fd") is not None:
            process["fd_topology"][str(payload["fd"])] = str(payload["fd_target"])
        if not process["tty"]:
            candidates = list(process["fd_topology"].values())
            process["tty"] = next((value for value in candidates
                                   if value.startswith(("/dev/pts/", "/dev/tty"))), "")
        if event.kind == "process_exec":
            process["exec"] = True
        elif event.kind == "process_exit":
            process["ended_at"] = event.recorded_at
            process["exit_code"] = payload.get("exit_code")
    for process in processes.values():
        if not process["start_ticks"]:
            process["confidence"] = max(20, process["confidence"] - 20)
        if process["exec"] and not process["argv"]:
            process["confidence"] = max(20, process["confidence"] - 15)
    return processes, event_process


def _is_tmux(process: dict, by_pid: dict[tuple[str, int], dict]) -> bool:
    seen = set()
    current = process
    while current and current["process_key"] not in seen:
        seen.add(current["process_key"])
        if _basename(current) == "tmux":
            return True
        current = by_pid.get((current["boot_id"], current.get("ppid") or -1))
    return False


def _upsert(db: Session, model, key_name: str, key: str, values: dict):
    row = db.scalar(select(model).where(getattr(model, key_name) == key))
    if row is None:
        row = model(**{key_name: key, **values})
        db.add(row)
    else:
        for name, value in values.items():
            setattr(row, name, value)
    db.flush()
    return row


def _sessions(db: Session, processes: dict[str, dict]) -> tuple[dict[str, TerminalSession], dict[str, str]]:
    grouped: dict[str, dict] = {}
    process_session: dict[str, str] = {}
    by_pid = {(item["boot_id"], item["pid"]): item for item in processes.values()}
    for process in processes.values():
        identity = _terminal_identity(process)
        if identity is None:
            continue
        _, key = identity
        process_session[process["process_key"]] = key
        session = grouped.setdefault(key, {
            "boot_id": process["boot_id"], "sid": process["sid"],
            "tty_nr": process["tty_nr"], "tty": process["tty"],
            "pid_namespace": process["pid_namespace"], "kind": "local",
            "process_keys": [], "observer_ids": set(), "losses": set(),
            "started_at": process["started_at"], "ended_at": process["ended_at"],
            "confidence": process["confidence"], "pgids": set(), "tmux_pids": [],
        })
        session["process_keys"].append(process["process_key"])
        session["observer_ids"].update(process["observer_ids"])
        session["losses"].update(process["losses"])
        session["started_at"] = min(session["started_at"], process["started_at"])
        session["confidence"] = min(session["confidence"], process["confidence"])
        if process["ended_at"] is None:
            session["ended_at"] = None
        elif session["ended_at"] is not None:
            session["ended_at"] = max(session["ended_at"], process["ended_at"])
        if process["pgid"] is not None:
            session["pgids"].add(process["pgid"])
        if _basename(process) == "tmux" and session["kind"] == "local":
            session["kind"] = "tmux-client"
            session["tmux_pids"].append(process["pid"])
        elif _is_tmux(process, by_pid):
            session["kind"] = "tmux-pane"
            session["tmux_pids"].append(process["pid"])
    rows = {}
    for key, session in grouped.items():
        if len(session["observer_ids"]) > 1:
            session["losses"].add("observer-restart")
            session["confidence"] = max(20, session["confidence"] - 15)
        topology = {"process_keys": sorted(session.pop("process_keys")),
                    "pgids": sorted(session.pop("pgids")),
                    "tmux_process_ids": sorted(set(session.pop("tmux_pids")))}
        observer_ids = sorted(session.pop("observer_ids"))
        losses = session.pop("losses")
        rows[key] = _upsert(db, TerminalSession, "session_key", key, {
            **session, "topology": json.dumps(topology, separators=(",", ":")),
            "observer_ids": json.dumps(observer_ids), "loss_state": _loss_state(losses),
        })
    return rows, process_session


def _persist_processes(db: Session, processes: dict[str, dict], sessions: dict[str, TerminalSession],
                       process_session: dict[str, str]) -> dict[str, ProcessInstance]:
    rows = {}
    for key, process in processes.items():
        values = {name: process[name] for name in (
            "boot_id", "pid", "tgid", "start_ticks", "ppid", "sid", "pgid",
            "tty_nr", "tpgid", "tty", "pid_namespace", "mount_namespace",
            "network_namespace", "user_namespace", "executable", "cwd",
            "started_at", "ended_at", "exit_code", "confidence")}
        session_key = process_session.get(key)
        values.update(
            terminal_session_id=sessions[session_key].id if session_key else None,
            cgroup=json.dumps(process["cgroup"], separators=(",", ":")),
            argv=json.dumps(process["argv"], ensure_ascii=False, separators=(",", ":")),
            fd_topology=json.dumps(process["fd_topology"], separators=(",", ":")),
            loss_state=_loss_state(process["losses"]),
            evidence_event_ids=json.dumps(sorted(set(process["event_ids"]))),
        )
        rows[key] = _upsert(db, ProcessInstance, "process_key", key, values)
    return rows


def _interactive_shell(process: dict) -> bool:
    if _basename(process) not in SHELLS:
        return False
    return "-c" not in process.get("argv", [])


def _fd(processes: list[dict], fd: str, reverse: bool = False) -> str:
    values = reversed(processes) if reverse else processes
    return next((item["fd_topology"].get(fd, "") for item in values
                 if item["fd_topology"].get(fd)), "")


def _command_groups(processes: dict[str, dict], process_session: dict[str, str]) -> list[dict]:
    grouped: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for process in sorted(processes.values(), key=lambda item: item["started_at"]):
        session_key = process_session.get(process["process_key"])
        if not session_key or not process["exec"] or _interactive_shell(process):
            continue
        grouped[(session_key, process.get("pgid") or process["pid"])].append(process)
    result = []
    for (session_key, pgid), members in grouped.items():
        members.sort(key=lambda item: (item["started_at"], item["pid"]))
        pipe_targets = [value for item in members for value in item["fd_topology"].values()
                        if value.startswith("pipe:[")]
        pipeline = len(members) > 1 and len(pipe_targets) != len(set(pipe_targets))
        command = " | ".join(shlex.join(item["argv"]) for item in members) if pipeline \
            else shlex.join(members[0]["argv"])
        evidence = sorted({event_id for item in members for event_id in item["event_ids"]})
        streams: dict[str, list[int]] = defaultdict(list)
        for item in members:
            for name, event_ids in item["evidence_streams"].items():
                streams[name].extend(event_ids)
        losses = {loss for item in members for loss in item["losses"]}
        tpgids = [item["tpgid"] for item in members if item["tpgid"] is not None]
        background = bool(tpgids and pgid > 0 and all(value != pgid for value in tpgids))
        first_event = min(evidence)
        inference = {"grouping": "terminal+pgid", "command_source": "exec-argv"}
        confidence = min(item["confidence"] for item in members)
        if pipeline:
            inference["pipeline"] = "shared-pipe-fd+pgid"
            inference["pipeline_order"] = "exec-time"
            confidence = min(confidence, 85)
        stdout = _fd(members, "1", reverse=True)
        if stdout and not stdout.startswith(("/dev/", "pipe:[", "socket:[")):
            inference["redirect"] = "stdout-fd-target"
        result.append({
            "activity_key": f"job:{session_key}:{pgid}:{first_event}",
            "session_key": session_key, "member_keys": [item["process_key"] for item in members],
            "kind": "pipeline" if pipeline else "command", "command": command,
            "cwd": members[0]["cwd"], "pgid": pgid, "is_pipeline": pipeline,
            "is_background": background, "stdin_target": _fd(members, "0"),
            "stdout_target": stdout, "stderr_target": _fd(members, "2", reverse=True),
            "evidence_event_ids": evidence, "inference": inference,
            "evidence_streams": {name: sorted(set(event_ids))
                                 for name, event_ids in streams.items()},
            "started_at": min(item["started_at"] for item in members),
            "ended_at": (max(item["ended_at"] for item in members)
                         if all(item["ended_at"] for item in members) else None),
            "confidence": max(20, confidence - (5 if background else 0)),
            "losses": losses, "sensitive": False,
        })
    return result


def _input_lines(events: list[RawActivityEvent], event_process: dict[int, str],
                 processes: dict[str, dict], process_session: dict[str, str]):
    buffers: dict[str, bytearray] = defaultdict(bytearray)
    evidence: dict[str, list[int]] = defaultdict(list)
    started: dict[str, datetime] = {}
    line_numbers: dict[int, int] = defaultdict(int)
    lines = []
    for event in sorted(events, key=lambda item: (item.recorded_at, item.monotonic_ns, item.id)):
        if event.kind != "stdio_read" or event.capture_state == "redacted":
            continue
        payload = _json(event.payload, {})
        encoded = payload.get("data_b64")
        process_key = event_process.get(event.id)
        if not encoded or not process_key or process_key not in process_session:
            continue
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            continue
        started.setdefault(process_key, event.recorded_at)
        evidence[process_key].append(event.id)
        buffers[process_key].extend(chunk)
        while b"\n" in buffers[process_key]:
            raw, _, rest = buffers[process_key].partition(b"\n")
            buffers[process_key] = bytearray(rest)
            text = raw.rstrip(b"\r").decode("utf-8", errors="replace").strip()
            event_ids = list(evidence[process_key])
            timestamp = started[process_key]
            evidence[process_key] = [event.id] if rest else []
            if rest:
                started[process_key] = event.recorded_at
            else:
                started.pop(process_key, None)
            if text:
                first_event = event_ids[0]
                line_number = line_numbers[first_event]
                line_numbers[first_event] += 1
                lines.append({"process_key": process_key,
                              "session_key": process_session[process_key],
                              "text": text, "event_ids": event_ids,
                              "line_number": line_number,
                              "started_at": timestamp, "ended_at": event.recorded_at})
    return lines


def _correlate_input(groups: list[dict], lines: list[dict],
                     processes: dict[str, dict]) -> list[dict]:
    unmatched = []
    used = set()
    for line in sorted(lines, key=lambda item: (item["ended_at"], item["started_at"]),
                       reverse=True):
        process = processes[line["process_key"]]
        remote = _basename(process) in SSH_NAMES
        candidates = [group for group in groups
                      if group["session_key"] == line["session_key"]
                      and group["activity_key"] not in used
                      and line["started_at"] - timedelta(milliseconds=250)
                      <= group["started_at"] <= line["ended_at"] + timedelta(seconds=5)]
        if candidates and not remote and _basename(process) in SHELLS:
            group = min(candidates, key=lambda item: item["started_at"])
            group["command"] = line["text"]
            group["evidence_event_ids"] = sorted(set(
                group["evidence_event_ids"] + line["event_ids"]))
            group["evidence_streams"].setdefault("stdin", [])
            group["evidence_streams"]["stdin"] = sorted(set(
                group["evidence_streams"]["stdin"] + line["event_ids"]))
            group["inference"]["pty_input"] = "correlated-not-proven"
            group["confidence"] = min(group["confidence"], 85)
            group["sensitive"] = True
            used.add(group["activity_key"])
            continue
        losses = set(process["losses"])
        confidence = min(process["confidence"], 50 if remote else 55)
        unmatched.append({
            "activity_key": f"input:{line['event_ids'][0]}:{line['line_number']}",
            "session_key": line["session_key"], "member_keys": [line["process_key"]],
            "kind": "remote-input" if remote else "shell-input",
            "command": line["text"], "cwd": process["cwd"], "pgid": process["pgid"],
            "is_pipeline": False, "is_background": False,
            "stdin_target": process["fd_topology"].get("0", ""),
            "stdout_target": process["fd_topology"].get("1", ""),
            "stderr_target": process["fd_topology"].get("2", ""),
            "evidence_event_ids": line["event_ids"],
            "evidence_streams": {"stdin": line["event_ids"]},
            "inference": {"command_source": "pty-input",
                          "execution": "unconfirmed", "remote": remote},
            "started_at": line["started_at"], "ended_at": line["ended_at"],
            "confidence": confidence, "losses": losses, "sensitive": True,
        })
    return groups + unmatched


def _persist_commands(db: Session, groups: list[dict], sessions: dict[str, TerminalSession],
                      process_rows: dict[str, ProcessInstance]) -> dict[str, CommandActivity]:
    rows = {}
    for group in groups:
        member_ids = [process_rows[key].id for key in group["member_keys"]]
        values = {name: group[name] for name in (
            "kind", "command", "cwd", "pgid", "is_pipeline", "is_background",
            "stdin_target", "stdout_target", "stderr_target", "started_at", "ended_at",
            "confidence", "sensitive")}
        values.update(
            terminal_session_id=sessions[group["session_key"]].id,
            primary_process_id=member_ids[0] if member_ids else None,
            process_instance_ids=json.dumps(member_ids),
            evidence_event_ids=json.dumps(sorted(set(group["evidence_event_ids"]))),
            evidence_streams=json.dumps(group["evidence_streams"], separators=(",", ":")),
            inference=json.dumps(group["inference"], separators=(",", ":")),
            loss_state=_loss_state(group["losses"]),
        )
        rows[group["activity_key"]] = _upsert(
            db, CommandActivity, "activity_key", group["activity_key"], values)
    return rows


def _ssh_destination(argv: list[str]) -> tuple[str, str]:
    takes_value = {"-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
                   "-L", "-l", "-m", "-O", "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w"}
    username = ""
    index = 1
    while index < len(argv):
        value = argv[index]
        if value in takes_value:
            if value == "-l" and index + 1 < len(argv):
                username = argv[index + 1]
            index += 2
            continue
        if value.startswith("-"):
            index += 1
            continue
        inline_user, separator, destination = value.rpartition("@")
        return (destination, inline_user) if separator else (value, username)
    return "", ""


def _remote_candidates(db: Session, processes: dict[str, dict], process_rows,
                       process_session, sessions, commands) -> set[str]:
    keys = set()
    for key, process in processes.items():
        if _basename(process) not in SSH_NAMES or key not in process_session:
            continue
        destination, username = _ssh_destination(process["argv"])
        activity = next((row for activity_key, row in commands.items()
                         if process_rows[key].id in _json(row.process_instance_ids, [])), None)
        candidate_key = f"ssh:{key}"
        _upsert(db, RemoteSessionCandidate, "candidate_key", candidate_key, {
            "terminal_session_id": sessions[process_session[key]].id,
            "process_instance_id": process_rows[key].id,
            "client_activity_id": activity.id if activity else None,
            "destination": destination, "username": username,
            "evidence_event_ids": json.dumps(sorted(set(process["event_ids"]))),
            "started_at": process["started_at"], "ended_at": process["ended_at"],
            "confidence": min(process["confidence"], 70),
            "loss_state": _loss_state(process["losses"]),
        })
        keys.add(candidate_key)
    return keys


def _prune(db: Session, model, key_column, current: set[str]) -> None:
    statement = delete(model)
    if current:
        statement = statement.where(key_column.not_in(current))
    db.execute(statement)


def reconstruct(db: Session) -> dict[str, int]:
    """Idempotently derive non-semantic terminal activity from the raw corpus."""
    # ponytail: full rebuild keeps the interface deterministic; add an event cursor
    # only when real corpus size makes this measurably slow.
    events = list(db.scalars(select(RawActivityEvent).order_by(
        RawActivityEvent.recorded_at, RawActivityEvent.monotonic_ns, RawActivityEvent.id)))
    if not events:
        return {"processes": 0, "sessions": 0, "commands": 0, "remote_candidates": 0}
    observer_loss = _losses(events)
    processes, event_process = _processes(events, observer_loss)
    sessions, process_session = _sessions(db, processes)
    process_rows = _persist_processes(db, processes, sessions, process_session)
    groups = _command_groups(processes, process_session)
    lines = _input_lines(events, event_process, processes, process_session)
    groups = _correlate_input(groups, lines, processes)
    commands = _persist_commands(db, groups, sessions, process_rows)
    remote_keys = _remote_candidates(
        db, processes, process_rows, process_session, sessions, commands)
    _prune(db, RemoteSessionCandidate, RemoteSessionCandidate.candidate_key, remote_keys)
    _prune(db, CommandActivity, CommandActivity.activity_key, set(commands))
    _prune(db, ProcessInstance, ProcessInstance.process_key, set(process_rows))
    _prune(db, TerminalSession, TerminalSession.session_key, set(sessions))
    db.commit()
    return {"processes": len(process_rows), "sessions": len(sessions),
            "commands": len(commands), "remote_candidates": len(remote_keys)}
