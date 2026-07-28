# Implementation Worklog

## 2026-07-28

### Phase 1 — Scan Center

- Audited the existing data model, runner, API, tests, and React screen.
- Restored owner write permission on the imported read-only project tree.
- Replaced deprecated naive UTC timestamp factories with aware UTC timestamps.
- Added scan aliases and user tags with an Alembic migration.
- Added safe artifact downloads and CSV/JSON observation exports.
- Added completed scan reruns based on validated stored Nmap argv.
- Reworked scan event subscriptions so multiple clients receive the same events.
- Added SSE snapshots and terminal-state replay for browser reconnection.
- Added queue/history status filters, elapsed time, cancellation, rerun, failure
  details, saved-output reopening, observation filters/sorting, artifact metadata,
  downloads, aliases, tags, and CSV/JSON exports to the Scan Center UI.
- Installed frontend dependencies with npm and fixed a pre-existing TSX generic
  parsing defect in both application entry screens.

Verification:

- Backend: `python3 -m pytest -q` — 10 passed, including artifact/export,
  metadata, and multi-subscriber event tests.
- Frontend: `npm run build` — TypeScript and Vite production build passed.
- Alembic: clean temporary SQLite database upgraded through revisions 0001–0003.

### Phase 2 — Service Enumeration (in progress)

- Added persistent per-service Markdown notes and tags.
- Added execution lifecycle status, errors, output paths, saved-output reopening,
  and output downloads.
- Expanded the reviewed static catalog across FTP, SSH, Telnet, SMTP, DNS,
  HTTP(S), SMB/RPC, NFS, LDAP/Kerberos, common databases, RDP/WinRM, SNMP,
  and unknown services.
- Added template tool, sudo, expected-output, risk, and OSCP policy metadata.
- Added service workspace editing and service-filtered execution history to the UI.
- Added PTY-backed SSH, FTP, Telnet, and smbclient sessions with xterm.js,
  resize handling, process-group termination, output-only logs, and session
  lifecycle metadata. Authentication input is deliberately not persisted.

Verification:

- Backend after Phase 2 batch: 10 passed.
- Frontend after Phase 2 batch: production build passed.

### Phase 3 — Web Testing Workspace

- Added saved user-authored HTTP requests, folders, tags, duplication, explicit
  variables, manual repeat count, TLS/proxy/timeout/redirect controls, and
  raw/JSON/form body modes.
- Added response history with status, timing, size, headers, cookies, SHA-256,
  raw-byte preservation/download, and response body viewing.
- Kept automatic payload generation, fuzzing, vulnerability detection, and
  success judgment outside the implementation.
- Added response preservation tests using a deterministic mock transport.

Verification: backend 12 passed; frontend production build passed; clean
Alembic upgrade through revision 0005 passed.

### Phase 4 — Evidence Management

- Added file, screenshot, command output, HTTP, Nmap, flag, attachment, and
  Markdown evidence records with source links, SHA-256, acquisition metadata,
  sensitivity, report inclusion, tags, and duplicate-hash references.
- Added drag-and-drop upload, image preview, metadata review, downloads, and
  selected evidence ZIP export with a JSON manifest.
- Added duplicate/hash/ZIP tests.

Verification: backend 13 passed; frontend production build passed; clean
Alembic upgrade through revision 0006 passed.

### Phase 5 — AD Information

- Added domains, users, groups, computers, shares, SPNs, sessions, trusts, and
  credential-source observations using a factual generic object model.
- Added CSV/JSON imports, search, notes, tags, attributes, and explicitly
  observed relationships with optional evidence references.
- No attack-path, privilege-escalation, or risk inference is performed.

### Phase 6 — Tunnels and Sessions

- Added user-confirmed SSH local, remote, and dynamic forwarding with safe argv,
  PID/status/log tracking, process-group termination, and restart recovery.
- Unified tunnel records with the existing interactive PTY session history.

### Phase 7 — Reporting

- Added user-authored Markdown reports, an OSCP structure template, evidence
  captions/index, screenshots, sensitive-information review, and HTML/PDF export.
- Report content, impact, reproduction steps, and judgment remain user-authored.

### Operations and final QA

- Added global factual search, local mutation auditing, artifact/database backup,
  persisted scan concurrency, and pre-Alembic database adoption.
- Added lazy-loaded frontend workspaces to keep the initial bundle small.
- Upgraded Vite/Vitest and removed unused React Router; `npm audit` reports zero
  known vulnerabilities.

Final verification:

- Isolated `.venv` installation completed successfully.
- `./scripts/test.sh`: 18 backend tests passed and the Vite 7 production build
  completed with route-level chunks.
- `pip check`: no broken requirements in the project virtual environment.
- `npm audit`: 0 vulnerabilities.
- Clean temporary database upgraded through Alembic revision `0011_settings`.
- Legacy unversioned database adoption stamped `0011_settings` without data loss.
- API smoke test created a project and target and verified policy/settings routes.
- Runtime smoke test started the production server under `timeout`, returned
  HTTP 200 for the policy API and built SPA, then shut down cleanly.
- Official OSCP+ Exam Guide, FAQ, and AI policy were re-checked on 2026-07-28;
  the product boundary remains consistent. Added `OSCP_POLICY.md` and an
  explicit warning that no LLM/chatbot may remain available during the exam or
  reporting period.
- Final Scan Center QA added separate stdout/stderr preservation, detailed
  factual change display/export, persisted configurable concurrency, bounded
  uploads/live output, partial artifact recovery, and queued-task cleanup.
- Final Web QA added explicit scope confirmation and factual response comparison.

Verification is recorded after each implementation batch. The repository remains
uncommitted because all imported project files were already untracked.
