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

The initial corpus exposed gaps: very short external commands in tmux panes did
not become CommandActivity rows, and some rapidly pasted PTY input became
garbled shell-input candidates. The collector now records `comm` at the kernel
exec tracepoint, reconstruction orders events by kernel monotonic time and may
inherit a missing terminal identity from a captured parent. When `/proc` argv
is gone, the command is only the executable basename, explicitly marked
`kernel-comm` with reduced confidence and `argv-unavailable` loss; arguments
are never invented. A redacted or partial PTY read discards the current line
and waits for the next newline before accepting another candidate. On the
Kali VM, 30 rapid `/usr/bin/true` executions missed userspace argv and all 30
were reconstructed as `true` with this provenance and one terminal session.
The temporary Graph retained its five existing nodes; no new host or project
claim was made for those unbound commands. While the observer's automatic sync ran,
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
| out-of-order fork/exec/exit with missing argv | kernel `comm` command, inherited parent PTY, reduced confidence |
| redacted PTY gap between fragments | no concatenated shell-input candidate |
| observer restart | same TerminalSession plus observer-restart loss state |
| event loss / sequence gap | loss state propagated and idempotent rebuild |
| truncated output | partial-capture state propagated |

The earlier passive targeted suite passed (`24 passed`), migration
`0045_session_reconstruction` passed fresh, hybrid and contaminated-schema
tests (`4 passed`), and the full backend suite passed (`604 passed`). On
2026-09-26 the updated passive, graph service and graph router subset passed
(`89 passed`). After the short-command fix the targeted subset passed
(`91 passed`), and the broader Kali VM backend run passed (`611 passed`) after
excluding two MongoDB test modules that could not collect without `pymongo`.

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
continue broader live coverage and attribution validation before adding semantic
parsers. The short-command and PTY-fragment defects above passed targeted and
live checks; the current corpus is not a universal coverage claim.

## 2026-09-26 sync and attribution follow-up

The 36k-event Kali corpus took 7.8 seconds for an explicit full rebuild. The
old automatic two-second sync interval could therefore saturate one uvicorn
core, especially while observing the server's own database activity. Idle sync
now skips reconstruction (0.065 seconds against this corpus); a batch sync
rewrites only affected terminal sessions and processes, with a full-rebuild
fallback for loss or changed terminal identity. The observer excludes the
backend PID but not its child commands, and coalesces pending batches over a
30-second interval. A five-second idle sample with the observer active showed
0.4% mean backend CPU, down from 100% before coalescing. This is a bounded
smoke measurement, not a long-duration throughput guarantee.

Local loopback HTTP fixture checks captured `curl -fsS ...` and `ffuf -w - ...`
as separate exact-argv CommandActivity rows. The fixture's `127.0.0.1` is not
evidence of a project host: Graph attribution now leaves loopback/localhost
commands unresolved even in a single-project workspace. No ffuf/curl semantic
parser or HTTP-result claim was added.
An actual Graph sync exposed 66 unrelated command nodes created by the old
single-project fallback. That fallback is removed: commands without a unique
non-loopback Target IP or observed endpoint remain in the raw command layer,
and a subsequent sync prunes previously inferred Graph nodes.
In the live smoke DB, the corrected Graph sync reduced 71 nodes to 5 and
removed all 66 `command_activity` nodes; the explicit legacy Nmap capture
remained.
During the sustained observer run, BCC reported perf-buffer loss and exposed
a callback signature mismatch. The callback now records dropped-event counts
in the loss stream instead of throwing; coverage claims must still be reduced
when a loss marker occurs.

## Nmap output modes in a real shell

An authorized loopback scan with `-oN path` still wrote a human port table to
stdout, so that mode did not reproduce a missing service. `nmap -oX -` did:
the old passive parser retained the XML bytes but marked the scan unresolved
with "no Nmap port-table observations found". The passive ingest now uses the
existing hardened XML parser for XML stdout and stores the XML as a hashed scan
artifact. The same loopback scan became `observed` with the service product
from XML; no Finding was created.

For the common `-oA prefix` and `-oX file` modes, the declared XML can enrich
the stdout observation. Only a fresh, regular, non-symlink, owner-owned XML
file of at most 10 MiB is read; the file must have been modified during the
observed execution window. XML and stdout become separate hashed Evidence.
Root-owned outputs are intentionally not imported by this path, and hostname,
range, or ambiguous-project scans remain unresolved rather than guessed.
In a live `-oA` loopback run, both XML and stdout became distinct ScanArtifact
and Evidence rows, the service product was retained, and Finding count stayed
zero. An initial run exposed that `SessionLocal(autoflush=False)` hid the new
stdout artifact from Evidence registration; an explicit flush fixed it and
the production-session regression test now checks for both Evidence rows.
The Kali backend run passed 621 tests with the two MongoDB modules excluded
because `pymongo` is not installed there; the final Nmap-targeted rerun passed
30 tests after tightening relative-path handling.
