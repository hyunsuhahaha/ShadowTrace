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

### Phase 8 — Korean UI and direct Kali workflow

- Changed the default UI language to Korean while preserving standard technical
  terms such as TCP, HTTP, Nmap, SSH, API, JSON, XML, PTY, and SHA-256.
- Removed marketing-style introductions and policy slogans from workspace
  headers.
- Reworked Scan Center around the direct workflow: select or add a target IP,
  choose a profile, review the generated Nmap command, execute it, then parse
  and preserve the generated XML automatically. Existing XML import is now a
  secondary action labelled as importing an existing Nmap result.
- Removed manual project selection from Scan Center. The first entry of an IP
  atomically creates a project named after that IP and its target; entering an
  existing IP selects the existing target without creating duplicates.
- Restored explicit project switching after clarifying that only project
  creation should be automatic. The Scan Center header now selects IP-named
  projects, switches the associated target and scan history together, and
  persists the selected project across reloads.
- Expanded built-in Nmap choices into quick common TCP, fast and balanced full
  TCP, selected-port version/detail/deep checks, privileged SYN variants, and a
  privileged top-100 UDP check. Each choice states its speed, accuracy, and
  privilege tradeoff. Privileged scans use the Kali Polkit authentication
  dialog; sudo credentials never pass through the browser or application API.
- Grouped Nmap choices as full TCP, top TCP, UDP, and specific ports. Top TCP
  and UDP counts are user-selected (`--top-ports`), while specific TCP/UDP
  accepts validated port lists and ranges. Full UDP is available with a clear
  long-running warning.
- Added `.ovpn` selection in Scan Center and Enumeration. The backend validates
  the OpenVPN client file, rejects command-execution directives, stores it
  outside the repository with restricted permissions, imports it through
  NetworkManager, connects it, reports `tun0`, and can disconnect only the
  connection managed by the app.

Verification: 30 backend tests passed, the frontend production build passed,
Python bytecode compilation passed, and `git diff --check` passed.

### Phase 9 — Exploit Research Workspace

- Added service-scoped public exploit candidate records with discovery evidence,
  affected-version and prerequisite notes, explicit validation/result states,
  structured modifications, sources, manual execution records, and Evidence
  links.
- Added an explicit single-service SearchSploit action. It checks installation,
  uses a fixed argv without a shell, limits input/output, applies a timeout, and
  preserves raw output when JSON parsing fails. Results are never registered or
  treated as vulnerabilities until the user selects one.
- Added guarded local Exploit-DB PoC import, immutable originals, independent
  working copies, hashes, text/binary and size checks, editing, and unified diff.
- Added a manual Bash PTY handoff that fills the command without sending Enter.
  The application does not expose a PoC execution endpoint.
- Added optional Research selection to Evidence and report workflows, masked
  sensitive values, and global search coverage.
- Added Alembic revision `0012_exploit_research` and backend/frontend regression,
  security, fallback, file-management, execution-record, and report tests.

Verification: 34 backend tests passed; 2 frontend tests passed; TypeScript and
the Vite production build passed. Fresh/upgrade/downgrade migration and runtime
API smoke results are recorded in the final task report.

## 2026-08-02

### Phase 10 — Backend/frontend modularization (stabilization)

A multi-session effort (Codex and Claude Code alternating on
`phase-8/stabilization`) to break `backend/app/main.py`, `App.tsx`, and other
large files into small, single-purpose modules without changing any URL,
request/response schema, or DB schema. Each step moved code only; behavior was
re-verified after every step.

Backend:
- Moved product/project/target/service metadata routes out of `main.py` into
  `backend/app/modules/core/router.py`, sharing `need()`/`safe_part()` via
  `backend/app/modules/core/support.py`.
- Moved Execution CRUD/output/SSE/stop routes into
  `backend/app/modules/executions/router.py`.
- Moved Interactive Session HTTP/WebSocket/desktop/PTY routes into
  `backend/app/modules/sessions/router.py` (PTY manager shutdown stays in the
  app lifespan in `main.py`).
- Split `backend/app/modules/runbooks/router.py` (1,185 lines) into
  `support.py` (shared Pydantic schemas, constants, and helpers),
  `workflow_router.py` (templates, instances, recommendations, findings,
  summary), `execution_router.py` (step status/approval/timer,
  evidence/execution/credential attachment, observations), and
  `credentials_router.py` (credential CRUD). All three keep the
  `/api/runbooks` prefix, so the route surface is unchanged; `main.py` now
  includes all three. Updated the handful of call sites that imported names
  from the old `runbooks.router` module (`service_intelligence/router.py`,
  `test_runbooks.py`, `test_targets.py`, `test_builtin_runbooks.py`).
- Moved the `TOOLS` dict and `/api/system/status` route into a new
  `backend/app/modules/system.py`. `main.py` shrank from 562 to 139 lines and
  now holds only app assembly, lifespan, the audit middleware, and static
  frontend serving.
- Replaced fake uploads in `test_directory.py`/`test_evidence.py` with real
  multipart-equivalent `SpooledTemporaryFile` fixtures, removing a Python
  3.13/AnyIO timeout.

Frontend (`App.tsx`, 2,062 → 1,110 lines):
- Extracted `enumerationModel.ts` (domain types, display constants, PTY
  `shellQuote`), `api.ts` (shared fetch handling), and
  `useEnumerationQueries.ts` (project→target→service→command/intelligence/
  execution queries).
- Extracted `ServiceList`, `ExecutionHistory`, `ExecutionMonitor`,
  `ServiceWorkspace`, `CommandReviewModal`, `EnumerationScope`,
  `CredentialAuditPanel`, `ServiceDashboard`, `InvestigationCommandList`,
  `ManualGuidance`, `JobStatus`, `CredentialStoreForm`, `NetexecOutcome`,
  `PrivescSessionPanel` (LinPEAS/WinPEAS server + psexec terminal), and
  `LiveOutputPanel` (live/status terminal output) — each with its own test
  file.

`ScanCenter.tsx` (1,131 → 603 lines):
- Extracted `scanCenterModel.ts` (types, constants, `get`/`serverTime`/
  `elapsed`/`bytes`/`syncSelectedProject`), `ScanToolPicker.tsx`,
  `ScanProfileComposer.tsx` (target registration, profile picker, Nmap XML
  import, command preview/review), `ScanJobStatus.tsx` (current scan status,
  automation/chaining/masscan-discovery notices), and `ScanHistoryPanel.tsx`
  (search/filter, queue/history list, cancel/rerun, diff comparison).
  `ScanCenter.test.ts` was renamed to `scanCenterModel.test.ts` to match its
  new home; `PostExploitationWorkspace.tsx`'s `syncSelectedProject` import was
  updated accordingly. The observation table/filters/stats, artifact panel,
  and output terminal were intentionally left in `ScanCenter.tsx`.

Verification after each step: full backend suite (125 passed), full Vitest
suite (grew from 19 to 39 files / 60 to 97 tests across the series), `tsc -b`,
and the Vite production build all passed. Each step was also checked live in
Chrome against an isolated DB/profile under `/tmp/oscp-browser-validation`
(Scan Center, Service Enumeration, Runbooks), confirming no console errors, no
failed asset/API requests, and — for the runbooks split — an actual
`PATCH /api/runbooks/steps/{id}` round trip updating the UI. `git diff
--check` passed throughout.

### Phase 11 — Golden-path integration tests, GraphWorkspace split, doc drift

Prompted by an external review noting `GraphWorkspace.tsx` had regrown to
2,112 lines while recent commits only tuned its visuals, that
`docs/ROADMAP.md` P0's integration-test items were still unmet, and that
`docs/ENGINEERING_ONBOARDING.md`'s "111개" command count no longer matched
`services.yaml` (130).

Docs:
- Fixed the catalog count and replaced `docs/ARCHITECTURE.md`'s stale module
  table with a pointer to `docs/ENGINEERING_ONBOARDING.md` §6/§11 (already
  accurate and file-scoped), so the same list stops being tracked in two
  places. §11.1 kept as a resolved-history note.

Backend: new `backend/tests/test_golden_path_integration.py` chains Nmap XML
import (`scan_center.service.import_xml`) → `Service` row → runbook
recommendation/apply → Evidence/Execution attach → Finding + `FindingEvidence`
→ report export, asserting the exported HTML actually contains the finding
title and evidence caption. Uses the same local `database()`/`scope()`
pattern as every other test file (no conftest.py introduced).

Frontend E2E: new `frontend/e2e/` Playwright suite (`golden-path.spec.ts`)
drives the real SPA — scan XML import, runbook apply, evidence upload —
against a non-root backend + throwaway SQLite spun up by
`global-setup.ts`/`global-teardown.ts` (never the root launcher, never the
developer's real workspace). Finding/report authoring is seeded via the
backend's own API rather than reproduced through form UI, since that CRUD
already has backend coverage. New `scripts/test-e2e.sh` keeps it out of the
fast `scripts/test.sh` path. Added `frontend/vitest.config.ts` to exclude
`e2e/**` from Vitest's default glob — first attempt merged in
`vite.config.ts` via `mergeConfig`, which broke cross-file Vitest isolation
at full-suite scale (an unrelated file's test started reading Graph test
fixture state); the standalone version doesn't have this problem.

`GraphWorkspace.tsx` (2,112 → 479 lines), same move-only approach as Phase
10: `graphModel.ts` (types/constants/pure helpers), `graphStyles.ts` (the `S`
style map), `graphLeaves.tsx` + `OutlineView.tsx` (small presentational
pieces), `GraphCanvas.tsx` (+`ActivityStream`), `Inspector.tsx`,
`GraphRequestPanel.tsx`. Existing tests moved with their code
(`graphModel.test.ts`, `Inspector.test.tsx`, `GraphRequestPanel.test.tsx`);
`GraphCanvas.tsx` had zero prior tests, so new `GraphCanvas.test.tsx` covers
mount/unmount/re-render via a stubbed Canvas 2D context (jsdom has none) —
force-sim physics and pixel output are left out of scope, same as this
repo's existing pragmatic-testing calls elsewhere.

Verification after each step: `tsc -b`, full Vitest (final: 86 files / 400
tests), Vite production build, full backend suite (416 passed, includes the
new integration test), the new Playwright spec, and live Chrome checks
(Progress Graph, Outline view, no console errors) against the developer's
running dev instance. A pre-existing (not introduced by this session) layout
bug was found and filed separately rather than fixed inline: the Activity
Stream panel renders squished when a project has no graph data yet,
reproduced identically on pre-refactor code via `git stash`.

### ShadowTrace Phase 1 — Passive Nmap MVP

Fork identity를 ShadowTrace로 분리한 뒤, Workspace 밖 Kali terminal에서 실행한
Nmap을 wrapper·output option 없이 관찰하는 최소 경로를 추가했다.

- `scripts/passive-observer.py`: BCC/eBPF tracepoint로 nmap exec, stdout/stderr write,
  exit를 수집해 0600 state inbox 파일로 보존.
- `modules/passive_activity`: 단일 literal IP의 표준 Nmap port table만 파싱,
  Project 해결이 유일할 때만 `PassiveActivity → ScanJob → Observation →
  Target/Service → Graph` 투영. 모호하면 `unresolved` 보존.
- `scan_center.apply_scan_hosts()` seam을 추출해 XML과 passive text parser가 같은
  Service upsert 규칙을 공유. Passive 경로는 Finding을 생성하지 않음.
- 검증: backend `583 passed`, frontend `104 files / 584 tests`, production build,
  Alembic 0043 전체·contaminated schema 복구, compileall, shell syntax.
  `python3-bpfcc`가 로컬에 없고 sudo 암호 입력이 필요해 live BPF load는 보류.
