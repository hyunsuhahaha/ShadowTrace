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

## Live capture preflight result — 2026-08-27

The repository preflight was executed on the current Kali host:

```text
kernel: 6.19.14+kali-amd64
BCC Python bindings: ready
matching headers: /lib/modules/6.19.14+kali-amd64/build — missing
exact header package in current APT metadata — missing
linux-headers-amd64 candidate: 7.0.12-2kali1
```

The required host change is therefore:

```bash
sudo apt update
sudo apt install linux-image-amd64 linux-headers-amd64
sudo reboot
```

After reboot:

```bash
uname -r
test -d /lib/modules/$(uname -r)/build
./scripts/passive-preflight.sh
./scripts/start.sh
./scripts/passive-live-smoke.py
```

No installation was performed. `sudo apt update` was attempted through the
approved command path but stopped at the interactive password prompt; the
password was not requested, captured or bypassed. Consequently BPF source
compile, attach and real event capture remain unverified on this host.

The live smoke script is ready for the post-reboot run. It opens a real PTY,
runs a normal Bash flow, creates and renames filesystem entries, makes a
loopback TCP connection, writes 5,000 bytes in one syscall, exits, calls
`POST /api/passive/sync`, and verifies DB-backed raw event rows for fork, exec,
exit, PTY read/write, connect, filesystem mutation and truncation.

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

The passive targeted suite passes (`24 passed`). Migration `0045_session_reconstruction`
passes fresh, hybrid and contaminated-schema tests (`4 passed`). The full backend
suite, including loopback integration and MongoDB-dependent tests, passes
(`604 passed`).

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

**No-go for ffuf, curl or Burp semantic parsers yet.** The generic reconstruction
interface and synthetic corpus are ready, but the required live BPF compile/load
and post-reboot smoke have not passed. After that smoke succeeds, the next gate
is a real-terminal corpus for two terminals, two tmux panes and an authorized
interactive SSH lab session. Semantic parsers should start only after those
flows remain separated and every loss/ambiguous case is visible without any
false Graph claim.
