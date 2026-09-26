# Passive Session Reconstruction Phase Report

## Outcome

ShadowTrace now has a derived evidence layer between raw endpoint events and
semantic observations:

```text
RawActivityEvent
  -> ProcessInstance
  -> TerminalSession
  -> CommandActivity
  -> Observation (not created by this phase)
  -> Entity / Relation (not created by this phase)
```

`RemoteSessionCandidate` is a side record for a local SSH process and its PTY
evidence. None of these derived records imports or mutates the Graph module.
The existing Nmap single-literal-IP projection remains the only automatic
semantic path.

## Reconstruction rules

`ProcessInstance` uses boot ID, PID/TGID and `/proc/PID/stat` start ticks as its
identity. It retains PPID, SID, PGID, foreground PGID, controlling TTY, PID,
mount, network and user namespaces, cgroup, cwd, argv, executable, standard-FD
targets and raw event IDs. Missing start ticks lower confidence instead of
silently merging a short-lived process with a later PID reuse.

`TerminalSession` is keyed by boot ID, PID namespace, SID and controlling TTY.
Observer ID is deliberately excluded, so restarting the observer does not split
the same live shell. Seeing multiple observer IDs adds `observer-restart` to the
loss state. tmux-related shells on different PTYs remain different sessions;
pane names and UI intent are not inferred.

`CommandActivity` groups external processes by TerminalSession and PGID. A
shared `pipe:[inode]` across standard FDs is required before the group is labeled
as a pipeline. Foreground PGID mismatch is evidence for a background candidate.
A non-PTY/non-pipe stdout FD target is recorded as redirect evidence. Input,
output and error targets remain distinct, and `evidence_streams` keeps separate
raw event ID lists for process, stdin, stdout, stderr, socket and filesystem.

PTY input is correlated to the closest subsequent external job in the same
session. Correlated text has confidence capped at 85 and is labeled
`correlated-not-proven`. Input with no exec evidence, including `cd`, remains a
`shell-input` candidate at confidence 55. Input read by a local SSH process is a
`remote-input` candidate at confidence 50. It is not proof that the remote shell
executed or accepted the string.

Observer sequence gaps, perf loss events, partial capture and observer restarts
are preserved in `loss_state`. Reconstruction is an idempotent full-corpus
upsert. This is intentionally simple; an incremental cursor should be added only
after real corpus size makes the rebuild measurably slow.

## Live capture result — 2026-09-26

The Kali VM still ran `6.19.14+kali-amd64`, but matching headers were now
present at `/lib/modules/6.19.14+kali-amd64/build`, and BCC Python bindings
were ready. No package installation or reboot was needed. Preflight passed;
the root observer compiled and loaded BPF on this kernel.

`passive-live-smoke.py` passed against the temporary local server. It opened a
real PTY, ran a Bash flow, changed files, made a loopback TCP connection and
wrote 5,000 bytes in one syscall. The API returned 264 events in that process
lineage with fork, exec, exit, PTY read/write, socket and filesystem kinds;
the truncated write was marked partial, and `missing` was empty.

Two simultaneous SSH terminal PTYs were `/dev/pts/2` and `/dev/pts/3`; each
produced a separate TerminalSession with its own `sleep 2` CommandActivity.
Two live tmux panes had separate PTYs and separate sessions (IDs 7 and 8);
each retained its own `sleep 4` command. An interactive SSH connection from
the VM to its own localhost created a separate local SSH session and one
RemoteSessionCandidate. These observations establish session separation for
this small authorized corpus, not universal activity coverage.

The corpus also exposed gaps: very short `true` commands in the tmux panes did
not become CommandActivity rows, and some rapidly pasted PTY input became
garbled shell-input candidates. While the observer's automatic sync ran,
overlapping manual `POST /api/passive/sync` calls sometimes returned HTTP 500;
the same endpoint completed after stopping the observer. A process-local lock
now serializes sync and reconstruct requests. A concurrent regression test
failed before the change and passed afterward; two concurrent requests to the
updated server on a separate port both returned HTTP 200 for one replayed
batch (one import with 48 skipped events, then an empty inbox). This lock
covers the supported single-worker server, not multiple server processes.

## Tests performed

Synthetic raw-event integration tests cover:

| Scenario | Expected reconstruction |
|---|---|
| plain Bash command | external ProcessInstance + confirmed-by-exec CommandActivity |
| shell builtin `cd` | low-confidence shell-input candidate only |
| `nmap ... | tee out.txt` | one pipeline with two ProcessInstances and shared pipe FD |
| redirect | stdout target retained; no semantic file-content claim |
| background job | PGID differs from foreground PGID |
| two terminals | two TerminalSessions |
| tmux two panes | two PTY-keyed tmux-pane sessions |
| interactive SSH | local SSH process + RemoteSessionCandidate |
| remote `whoami`, `sudo -l` | low-confidence remote-input candidates |
| local `sudo -l` | PTY text correlated with local sudo exec, no privilege claim |
| short-lived process | ProcessInstance retained with reduced confidence |
| observer restart | same TerminalSession plus observer-restart loss state |
| event loss / sequence gap | loss state propagated and idempotent rebuild |
| truncated output | partial-capture state propagated |

The earlier passive targeted suite passed (`24 passed`), migration
`0045_session_reconstruction` passed fresh, hybrid and contaminated-schema
tests (`4 passed`), and the full backend suite passed (`604 passed`). On
2026-09-26 the updated passive, graph service and graph router subset passed
(`89 passed`); the full suite was not rerun.

## Known ambiguous and failed cases

- The collector covers `read` on fd 0 and `write` on fd 1/2, not `readv`,
  `writev`, arbitrary application FDs, splice/sendfile or mmap I/O.
- PGID plus a shared pipe FD is strong topology evidence but does not encode the
  original shell AST. Pipeline order uses exec time and is explicitly inferred.
- Redirect evidence identifies the observed FD target, not whether all bytes
  reached durable storage.
- The userspace ECHO check can race with terminal-mode restoration. Redaction is
  risk reduction, not a secret-noncapture guarantee.
- tmux panes are separated by PTY, but pane names, windows, attach history and
  user intent are not reconstructed.
- A local SSH process and PTY plaintext support a remote-session candidate only.
  Transport ciphertext is untouched; remote background work and detached remote
  tmux remain invisible.
- Raw output may contain secrets and is protected only by local filesystem
  permissions. Encryption and retention policy remain future work.

## Semantic parser readiness

**No-go for ffuf, curl or Burp semantic parsers yet.** BPF load, live smoke and
the small two-terminal, two-pane and SSH corpus passed. The next gate is to
reproduce and fix missing short-lived commands and garbled PTY candidates,
then verify that live Graph attribution makes no false project or host claim.
