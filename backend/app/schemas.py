import re
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, IPvAnyAddress, field_validator

class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120, pattern=r"^[\w ._-]+$")
    description: str = Field(default="", max_length=4000)
class ProjectOut(ProjectIn, ORM):
    id: int
    created_at: datetime
    metasploit_target_id: int | None = None
    metasploit_locked_at: datetime | None = None

class MetasploitLockIn(BaseModel):
    target_id: int | None = None

class TargetIn(BaseModel):
    project_id: int
    name: str = Field(min_length=1, max_length=120, pattern=r"^[\w ._-]+$")
    ip: str
    hostname: str = Field(default="", max_length=253)
    os_guess: str = Field(default="", max_length=200)
    vpn: str = Field(default="tun0", max_length=80)
    notes: str = Field(default="", max_length=20000)
    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        return str(IPvAnyAddress(v))
class TargetOut(TargetIn, ORM):
    id: int
    updated_at: datetime

class TargetHostnameIn(BaseModel):
    hostname: str = Field(default="", max_length=253)

class TargetEnsureIn(BaseModel):
    ip: str
    name: str = Field(default="", max_length=120, pattern=r"^[\w ._-]*$")
    project_id: int | None = None

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        return str(IPvAnyAddress(v))

class ServiceOut(ORM):
    id: int; target_id: int; port: int; protocol: str; state: str
    name: str; product: str; version: str; extra_info: str; scripts: str
    cpe: str; tls: bool; detection_evidence: str; notes: str; tags: str

class ServiceUpdate(BaseModel):
    product: str | None = Field(default=None, max_length=200)
    version: str | None = Field(default=None, max_length=100)
    notes: str = Field(default="", max_length=50000)
    tags: list[str] = Field(default_factory=list, max_length=30)

class ExecutionIn(BaseModel):
    target_id: int
    service_id: int | None = None
    template_id: str = Field(pattern=r"^[a-z0-9-]+$")
    variables: dict[str, str] = {}
    run_as_root: bool = True
    output_filename: str = Field(default="", max_length=120, pattern=r"^[\w .-]*$")
class ExecutionOut(ORM):
    id: int; target_id: int; service_id: int | None; template_id: str
    command: str; stdout: str; stderr: str; cwd: str
    started_at: datetime; ended_at: datetime | None; exit_code: int | None; stopped: bool
    status: str; error: str; output_path: str

class ExecutionDeriveIn(BaseModel):
    content: str = Field(min_length=1, max_length=5_000_000)
    filename: str = Field(min_length=1, max_length=120, pattern=r"^[\w .-]+$")

class ScanProfileOut(ORM):
    id: int; name: str; kind: str; description: str; arguments: str; builtin: bool
    engine: str; chain_kind: str

class ScanPreviewIn(BaseModel):
    target_id: int
    profile_id: int
    ports: str = ""
    top_ports: int = Field(default=100, ge=1, le=65535)
    extra_arguments: list[str] = []

class ScanJobOut(ORM):
    id: int; project_id: int; target_id: int; profile_id: int | None
    parent_scan_id: int | None
    source: str; status: str; command: str
    started_at: datetime | None; ended_at: datetime | None
    exit_code: int | None; stopped: bool; error: str
    alias: str; tags: str; created_at: datetime

class ScanJobUpdate(BaseModel):
    alias: str = Field(default="", max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("tags")
    @classmethod
    def valid_tags(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            value = value.strip()
            if not value or len(value) > 40:
                raise ValueError("Tags must contain 1 to 40 characters")
            if value not in cleaned:
                cleaned.append(value)
        return cleaned

class ScanSettings(BaseModel):
    concurrency: int = Field(ge=1, le=8)

class ScanArtifactOut(ORM):
    id: int; scan_job_id: int; kind: str; path: str; sha256: str
    size: int; original_name: str; created_at: datetime

class ObservationOut(ORM):
    id: int; scan_job_id: int; target_id: int; port: int; protocol: str
    state: str; name: str; product: str; version: str; extra_info: str
    scripts: str; cpe: str; tls: bool; detection_evidence: str; observed_at: datetime

class InteractiveSessionIn(BaseModel):
    target_id: int
    service_id: int | None = None
    template_id: str = Field(pattern=r"^[a-z0-9-]+$")
    variables: dict[str, str] = Field(default_factory=dict)
    run_as_root: bool = True

class InteractiveSessionOut(ORM):
    id: int; target_id: int; service_id: int | None; template_id: str
    command: str; cwd: str; status: str; pid: int | None
    started_at: datetime | None; ended_at: datetime | None
    exit_code: int | None; log_path: str; error: str

class ManualTerminalIn(BaseModel):
    target_id: int
    service_id: int
    # Only for commands with no secret in argv — a caller that needs -p/-H
    # style credentials belongs on the embedded-panel path instead, which
    # types them into the PTY rather than storing them in a process's argv
    # or this row's command column.
    command: str = Field(default="", max_length=500)
    @field_validator("command")
    @classmethod
    def no_inline_secrets(cls, v: str) -> str:
        if re.search(r"(^|\s)(-p|--password|-H|--hash)(\s|=|$)", v, re.IGNORECASE):
            raise ValueError("Commands with an inline password/hash flag are not allowed here")
        return v

class DesktopLaunchIn(BaseModel):
    # Handed to the spawned command's own interactive password prompt
    # through a named pipe (see type_relay.exp) -- never written to this
    # row, a process's argv, or an environment variable.
    type_after: str = Field(default="", max_length=200)

class HttpRequestIn(BaseModel):
    project_id: int
    target_id: int
    service_id: int | None = None
    name: str = Field(min_length=1, max_length=160)
    folder: str = Field(default="", max_length=160)
    tags: list[str] = Field(default_factory=list, max_length=30)
    method: str = Field(default="GET", pattern=r"^[A-Z]+$", max_length=12)
    url: HttpUrl
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=2_000_000)
    body_mode: str = Field(default="raw", pattern=r"^(raw|json|form)$")
    tls_verify: bool = True
    proxy: str = Field(default="", max_length=2000)
    timeout: int = Field(default=30, ge=1, le=300)
    follow_redirects: bool = False

class HttpRequestOut(ORM):
    id: int; project_id: int; target_id: int; service_id: int | None
    name: str; folder: str; tags: str; method: str; url: str
    query: str; headers: str; cookies: str; body: str; body_mode: str
    tls_verify: bool; proxy: str; timeout: int; follow_redirects: bool
    created_at: datetime; updated_at: datetime

class ProxyCaptureOut(HttpRequestOut):
    # Cloud-storage fingerprint of this request's latest captured response,
    # so the proxy capture list can flag it without opening the request.
    # None means either no response has come back yet (has_response=False)
    # or one has, but nothing was detected (has_response=True) — the two
    # are visually distinct in the UI so a quiet row doesn't read as a
    # stuck capture.
    cloud_fingerprint: dict | None = None
    has_response: bool = False

class HttpSendIn(BaseModel):
    variables: dict[str, str] = Field(default_factory=dict)
    repeat: int = Field(default=1, ge=1, le=20)
    confirmed: bool

class PayloadRuleIn(BaseModel):
    type: str = Field(pattern=r"^(prefix|suffix|lower|upper|url_encode|base64|replace|regex_replace)$")
    value: str = Field(default="", max_length=10000)
    replacement: str = Field(default="", max_length=10000)

class PayloadPositionIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    candidates: list[str] = Field(min_length=1, max_length=100)
    rules: list[PayloadRuleIn] = Field(default_factory=list, max_length=20)

class IntruderRunIn(BaseModel):
    run_id: str = Field(pattern=r"^[A-Za-z0-9-]{8,64}$")
    attack_type: str = Field(pattern=r"^(sniper|battering_ram|pitchfork|cluster_bomb)$")
    positions: list[PayloadPositionIn] = Field(min_length=1, max_length=20)
    max_requests: int = Field(default=20, ge=1, le=100)
    delay_ms: int = Field(default=500, ge=100, le=60_000)
    grep_strings: list[str] = Field(default_factory=list, max_length=20)
    grep_regexes: list[str] = Field(default_factory=list, max_length=20)
    retry_count: int = Field(default=0, ge=0, le=2)
    stop_status_codes: list[int] = Field(default_factory=list, max_length=20)
    stop_string: str = Field(default="", max_length=1000)
    confirmed: bool

class HttpExchangeOut(ORM):
    id: int; request_id: int; status_code: int | None
    duration_ms: int; size: int; request_snapshot: str
    response_headers: str; response_cookies: str; body_path: str
    sha256: str; error: str; review_status: str; created_at: datetime
    cloud_fingerprint: dict | None = None

class ExchangeReviewIn(BaseModel):
    review_status: Literal["pending", "confirmed", "dismissed"]

class ProxyStartIn(BaseModel):
    project_id: int
    target_id: int
    port: int = Field(default=8081, ge=1024, le=65535)

class ProxyCaptureIn(BaseModel):
    project_id: int
    target_id: int
    method: str = Field(max_length=12)
    url: str = Field(max_length=4000)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=15_000_000)
    status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_cookies: dict[str, str] = Field(default_factory=dict)
    response_body: str = Field(default="", max_length=15_000_000)
    duration_ms: int = Field(default=0, ge=0)

class EvidenceOut(ORM):
    id: int; project_id: int; target_id: int; service_id: int | None
    title: str; description: str; kind: str; source_type: str
    source_id: int | None; file_path: str; original_name: str
    sha256: str; size: int; acquired_at: datetime; username: str
    hostname: str; privilege: str; sensitivity: str
    include_report: bool; tags: str; markdown: str
    duplicate_of: int | None
    exploit_research_id: int | None

class EvidenceUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20000)
    service_id: int | None = None
    username: str = Field(default="", max_length=160)
    hostname: str = Field(default="", max_length=253)
    privilege: str = Field(default="", max_length=80)
    sensitivity: str = Field(default="normal",
                             pattern=r"^(normal|sensitive|secret)$")
    include_report: bool = False
    tags: list[str] = Field(default_factory=list, max_length=50)
    markdown: str = Field(default="", max_length=200000)

class DirectoryObjectIn(BaseModel):
    project_id: int
    target_id: int | None = None
    kind: str = Field(pattern=r"^(domain|user|group|computer|share|spn|session|trust|credential_source)$")
    name: str = Field(min_length=1, max_length=300)
    domain: str = Field(default="", max_length=253)
    attributes: dict[str, str | int | bool | None] = Field(default_factory=dict)
    notes: str = Field(default="", max_length=50000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    source: str = Field(default="manual", max_length=120)

class DirectoryObjectOut(ORM):
    id: int; project_id: int; target_id: int | None; kind: str
    name: str; domain: str; attributes: str; notes: str; tags: str
    source: str; created_at: datetime

class DirectoryRelationIn(BaseModel):
    project_id: int
    source_id: int
    target_id: int
    relation: str = Field(min_length=1, max_length=100)
    evidence_id: int | None = None
    notes: str = Field(default="", max_length=20000)

class DirectoryRelationOut(DirectoryRelationIn, ORM):
    id: int
    observed_at: datetime

class TunnelIn(BaseModel):
    project_id: int
    target_id: int
    name: str = Field(min_length=1, max_length=160)
    kind: str = Field(pattern=r"^(local|remote|dynamic)$")
    ssh_host: str = Field(min_length=1, max_length=253,
                          pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=160,
                          pattern=r"^[A-Za-z0-9_.@-]+$")
    bind_host: str = Field(default="127.0.0.1",
                           pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    local_port: int = Field(ge=1, le=65535)
    remote_host: str = Field(default="", max_length=253,
                             pattern=r"^$|^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    remote_port: int | None = Field(default=None, ge=1, le=65535)
    confirmed: bool

class TunnelOut(ORM):
    id: int; project_id: int; target_id: int; name: str; kind: str
    ssh_host: str; ssh_port: int; username: str; bind_host: str
    local_port: int; remote_host: str; remote_port: int | None
    command: str; status: str; pid: int | None; log_path: str; error: str
    created_at: datetime; started_at: datetime | None; ended_at: datetime | None

class ReportEvidenceLink(BaseModel):
    id: int = Field(gt=0)
    caption: str = Field(default="", max_length=1000)

class ReportIn(BaseModel):
    project_id: int
    title: str = Field(min_length=1, max_length=200)
    template: str = Field(default="oscp", pattern=r"^(oscp|blank)$")
    markdown: str = Field(default="", max_length=2_000_000)
    evidence_links: list[ReportEvidenceLink] = Field(
        default_factory=list, max_length=1000)
    exploit_research_links: list[int] = Field(
        default_factory=list, max_length=500)
    sensitivity_reviewed: bool = False

class ReportOut(ORM):
    id: int; project_id: int; title: str; template: str; markdown: str
    evidence_links: str; exploit_research_links: str; sensitivity_reviewed: bool
    created_at: datetime; updated_at: datetime

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Disclosure = Literal["CLIENT", "INTERNAL", "BOTH"]

class FindingTemplateIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(default="", max_length=120)
    severity: Severity = "Informational"
    cvss_vector: str = Field(default="", max_length=160)
    description: str = Field(default="", max_length=100000)
    impact: str = Field(default="", max_length=100000)
    recommendation: str = Field(default="", max_length=100000)
    references: list[str] = Field(default_factory=list, max_length=100)
    cwe: str = Field(default="", max_length=80)
    cve: str = Field(default="", max_length=80)
    mitre_attack: list[str] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=50)

class FindingEvidenceIn(BaseModel):
    evidence_id: int = Field(gt=0)
    caption: str = Field(default="", max_length=2000)
    display_order: int = Field(default=0, ge=0)
    include_client: bool = False
    include_internal: bool = True
    is_primary: bool = False
    phase: Literal["BEFORE", "AFTER"] = "BEFORE"

class FindingIn(BaseModel):
    project_id: int
    target_id: int | None = None
    service_id: int | None = None
    target_ids: list[int] = Field(default_factory=list, max_length=500)
    service_ids: list[int] = Field(default_factory=list, max_length=1000)
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(default="", max_length=120)
    severity: Severity = "Informational"
    cvss_version: Literal["3.1"] = "3.1"
    cvss_vector: str = Field(default="", max_length=160)
    final_risk: Severity = "Informational"
    risk_override_reason: str = Field(default="", max_length=20000)
    summary: str = Field(default="", max_length=100000)
    description: str = Field(default="", max_length=100000)
    business_impact: str = Field(default="", max_length=100000)
    technical_impact: str = Field(default="", max_length=100000)
    reproduction_steps: str = Field(default="", max_length=200000)
    recommendation: str = Field(default="", max_length=100000)
    references: list[str] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=50)
    status: Literal["Draft", "Confirmed", "Needs Review", "Remediated", "Accepted Risk", "False Positive"] = "Draft"
    disclosure: Disclosure = "BOTH"
    internal_notes: str = Field(default="", max_length=200000)
    sort_priority: int = Field(default=0, ge=-100000, le=100000)
    evidence: list[FindingEvidenceIn] = Field(default_factory=list, max_length=500)

class FindingRetestIn(BaseModel):
    tester: str = Field(min_length=1, max_length=160)
    result: str = Field(min_length=1, max_length=40)
    remediated: bool = False
    notes: str = Field(default="", max_length=100000)
    before_evidence_ids: list[int] = Field(default_factory=list, max_length=500)
    after_evidence_ids: list[int] = Field(default_factory=list, max_length=500)

class ImageEditIn(BaseModel):
    operations: list[dict] = Field(default_factory=list, max_length=500)
    caption: str = Field(default="", max_length=2000)
    rendered_png_base64: str = Field(default="", max_length=20_000_000)
