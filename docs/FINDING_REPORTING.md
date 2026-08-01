# Finding-centered reporting

Reports now render project Findings through either a `client` or `internal`
profile. Existing Markdown reports and their Evidence links remain intact.

## Data and security

- Finding Templates are copied into `Finding.template_snapshot` when applied.
- Finding/Evidence, retest Evidence, Target, and Service links are rejected when
  they cross project boundaries.
- Client API serialization and report rendering independently remove internal
  Findings, internal-only links, sensitive Evidence, and internal notes.
- Screenshot edits are append-only JSON versions tied to the immutable original
  SHA-256. The original file is never modified.
- Markdown is HTML-escaped before rendering. Report fields are also escaped.

## API overview

- `/api/findings`, `/api/findings/{id}`, `/api/findings/bulk-status`
- `/api/findings/{id}/retests`
- `/api/finding-templates` plus clone, import, export, and apply routes
- `/api/cvss?vector=...`
- `/api/projects/{id}/finding-summary`
- `/api/evidence/{id}/image-edits`
- `/api/reports/{id}/export?format=pdf&profile=client|internal`

Template import accepts validated JSON request bodies. YAML export is available;
YAML files should be parsed by a client and submitted as JSON.

## UI workflow

The Reports workspace provides Finding triage and scoped Target/Service
selection, CVSS validation, per-Evidence disclosure and ordering, accumulated
retest history, full Finding Template management, and side-by-side profile
preview/export controls. Existing databases must be upgraded through
`0021_finding_observation_nullable`.

## Current limits

CVSS 3.1 base metrics are supported through metric controls or direct vectors;
temporal/environmental metrics and CVSS 4.0 are not. The image editor supports
crop, box, arrow, text, mosaic, undo/redo, deletion, and versioned PNG
derivatives without modifying original Evidence. Findings support multiple
Targets and Services, bulk status changes, template management, retest history,
Evidence ordering and visibility, statistics, profile preview, and export.
# Automatic scan evidence

Completed and imported Nmap scans are post-processed automatically:

- XML, normal, grepable, stdout, and stderr artifacts are registered as immutable Evidence.
- Explicitly positive security NSE results create a finding-specific Evidence excerpt.
- Each positive result creates an `INTERNAL` / `Needs Review` Finding candidate linked to its Target, Service, and Evidence.
- Reprocessing is idempotent. A scan cannot create duplicate Evidence or Finding candidates.
- Negative or informational NSE output does not create a Finding.

Candidates remain excluded from client reports until a tester validates and reclassifies them.
