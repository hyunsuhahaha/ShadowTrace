from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base
from .time import utcnow

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    targets: Mapped[list["Target"]] = relationship(cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(120))
    ip: Mapped[str] = mapped_column(String(45))
    hostname: Mapped[str] = mapped_column(String(253), default="")
    os_guess: Mapped[str] = mapped_column(String(200), default="")
    vpn: Mapped[str] = mapped_column(String(80), default="tun0")
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    services: Mapped[list["Service"]] = relationship(cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(12), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    name: Mapped[str] = mapped_column(String(80), default="unknown")
    product: Mapped[str] = mapped_column(String(200), default="")
    version: Mapped[str] = mapped_column(String(100), default="")
    extra_info: Mapped[str] = mapped_column(Text, default="")
    scripts: Mapped[str] = mapped_column(Text, default="")
    cpe: Mapped[str] = mapped_column(Text, default="[]")
    tls: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_evidence: Mapped[str] = mapped_column(Text, default="{}")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")

class Execution(Base):
    __tablename__ = "executions"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    template_id: Mapped[str] = mapped_column(String(100))
    command: Mapped[str] = mapped_column(Text)
    stdout: Mapped[str] = mapped_column(Text, default="")
    stderr: Mapped[str] = mapped_column(Text, default="")
    cwd: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stopped: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    error: Mapped[str] = mapped_column(Text, default="")
    output_path: Mapped[str] = mapped_column(Text, default="")

class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text, default="")
    arguments: Mapped[str] = mapped_column(Text)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("scan_profiles.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(20), default="executed")
    status: Mapped[str] = mapped_column(String(20), default="queued")
    command: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stopped: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    alias: Mapped[str] = mapped_column(String(120), default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    kind: Mapped[str] = mapped_column(String(20))
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    original_name: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class HostObservation(Base):
    __tablename__ = "host_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    ip: Mapped[str] = mapped_column(String(45))
    hostname: Mapped[str] = mapped_column(String(253), default="")
    os_guess: Mapped[str] = mapped_column(String(200), default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ServiceObservation(Base):
    __tablename__ = "service_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(12), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    name: Mapped[str] = mapped_column(String(80), default="unknown")
    product: Mapped[str] = mapped_column(String(200), default="")
    version: Mapped[str] = mapped_column(String(100), default="")
    extra_info: Mapped[str] = mapped_column(Text, default="")
    scripts: Mapped[str] = mapped_column(Text, default="")
    cpe: Mapped[str] = mapped_column(Text, default="[]")
    tls: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_evidence: Mapped[str] = mapped_column(Text, default="{}")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class InteractiveSession(Base):
    __tablename__ = "interactive_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    template_id: Mapped[str] = mapped_column(String(100))
    command: Mapped[str] = mapped_column(Text)
    cwd: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="ready")
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    log_path: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")

class HttpRequest(Base):
    __tablename__ = "http_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(160))
    folder: Mapped[str] = mapped_column(String(160), default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    method: Mapped[str] = mapped_column(String(12), default="GET")
    url: Mapped[str] = mapped_column(Text)
    query: Mapped[str] = mapped_column(Text, default="{}")
    headers: Mapped[str] = mapped_column(Text, default="{}")
    cookies: Mapped[str] = mapped_column(Text, default="{}")
    body: Mapped[str] = mapped_column(Text, default="")
    body_mode: Mapped[str] = mapped_column(String(20), default="raw")
    tls_verify: Mapped[bool] = mapped_column(Boolean, default=True)
    proxy: Mapped[str] = mapped_column(Text, default="")
    timeout: Mapped[int] = mapped_column(Integer, default=30)
    follow_redirects: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class HttpExchange(Base):
    __tablename__ = "http_exchanges"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("http_requests.id"))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    size: Mapped[int] = mapped_column(Integer, default=0)
    request_snapshot: Mapped[str] = mapped_column(Text)
    response_headers: Mapped[str] = mapped_column(Text, default="{}")
    response_cookies: Mapped[str] = mapped_column(Text, default="{}")
    response_body: Mapped[bytes] = mapped_column(LargeBinary, default=b"")
    body_path: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(40))
    source_type: Mapped[str] = mapped_column(String(40), default="upload")
    source_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str] = mapped_column(Text, default="")
    original_name: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    username: Mapped[str] = mapped_column(String(160), default="")
    hostname: Mapped[str] = mapped_column(String(253), default="")
    privilege: Mapped[str] = mapped_column(String(80), default="")
    sensitivity: Mapped[str] = mapped_column(String(20), default="normal")
    include_report: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[str] = mapped_column(Text, default="[]")
    markdown: Mapped[str] = mapped_column(Text, default="")
    duplicate_of: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    exploit_research_id: Mapped[int | None] = mapped_column(
        ForeignKey("exploit_research.id"), nullable=True)

class DirectoryObject(Base):
    __tablename__ = "directory_objects"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(30))
    name: Mapped[str] = mapped_column(String(300))
    domain: Mapped[str] = mapped_column(String(253), default="")
    attributes: Mapped[str] = mapped_column(Text, default="{}")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    source: Mapped[str] = mapped_column(String(120), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class DirectoryRelation(Base):
    __tablename__ = "directory_relations"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    source_id: Mapped[int] = mapped_column(ForeignKey("directory_objects.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("directory_objects.id"))
    relation: Mapped[str] = mapped_column(String(100))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Tunnel(Base):
    __tablename__ = "tunnels"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(20))
    ssh_host: Mapped[str] = mapped_column(String(253))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(160))
    bind_host: Mapped[str] = mapped_column(String(45), default="127.0.0.1")
    local_port: Mapped[int] = mapped_column(Integer)
    remote_host: Mapped[str] = mapped_column(String(253), default="")
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="ready")
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    log_path: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    title: Mapped[str] = mapped_column(String(200))
    template: Mapped[str] = mapped_column(String(40), default="oscp")
    markdown: Mapped[str] = mapped_column(Text, default="")
    evidence_links: Mapped[str] = mapped_column(Text, default="[]")
    exploit_research_links: Mapped[str] = mapped_column(Text, default="[]")
    sensitivity_reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class FindingTemplate(Base):
    __tablename__ = "finding_templates"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(120), default="")
    severity: Mapped[str] = mapped_column(String(20), default="Informational")
    cvss_vector: Mapped[str] = mapped_column(String(160), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="[]")
    cwe: Mapped[str] = mapped_column(String(80), default="")
    cve: Mapped[str] = mapped_column(String(80), default="")
    mitre_attack: Mapped[str] = mapped_column(Text, default="[]")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    observation_id: Mapped[int | None] = mapped_column(
        ForeignKey("runbook_observations.id"), unique=True, nullable=True)
    template_id: Mapped[int | None] = mapped_column(ForeignKey("finding_templates.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(120), default="")
    severity: Mapped[str] = mapped_column(String(20), default="Informational")
    cvss_version: Mapped[str] = mapped_column(String(10), default="3.1")
    cvss_vector: Mapped[str] = mapped_column(String(160), default="")
    cvss_score: Mapped[str] = mapped_column(String(8), default="0.0")
    final_risk: Mapped[str] = mapped_column(String(20), default="Informational")
    risk_override_reason: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    business_impact: Mapped[str] = mapped_column(Text, default="")
    technical_impact: Mapped[str] = mapped_column(Text, default="")
    reproduction_steps: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="[]")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(30), default="candidate")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    retested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retest_result: Mapped[str] = mapped_column(Text, default="")
    disclosure: Mapped[str] = mapped_column(String(10), default="BOTH")
    internal_notes: Mapped[str] = mapped_column(Text, default="")
    sort_priority: Mapped[int] = mapped_column(Integer, default=0)
    template_snapshot: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    caption: Mapped[str] = mapped_column(Text, default="")
    display_order: Mapped[int] = mapped_column(Integer, default=0)
    include_client: Mapped[bool] = mapped_column(Boolean, default=False)
    include_internal: Mapped[bool] = mapped_column(Boolean, default=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    phase: Mapped[str] = mapped_column(String(10), default="BEFORE")

class FindingAsset(Base):
    __tablename__ = "finding_assets"
    __table_args__ = (UniqueConstraint("finding_id", "target_id", "service_id",
                                       name="uq_finding_asset"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), nullable=True)

class FindingRetest(Base):
    __tablename__ = "finding_retests"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    tested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    tester: Mapped[str] = mapped_column(String(160))
    result: Mapped[str] = mapped_column(String(40))
    remediated: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    before_evidence_ids: Mapped[str] = mapped_column(Text, default="[]")
    after_evidence_ids: Mapped[str] = mapped_column(Text, default="[]")

class EvidenceImageEdit(Base):
    __tablename__ = "evidence_image_edits"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    operations: Mapped[str] = mapped_column(Text, default="[]")
    original_sha256: Mapped[str] = mapped_column(String(64))
    rendered_path: Mapped[str] = mapped_column(Text, default="")
    rendered_sha256: Mapped[str] = mapped_column(String(64), default="")
    caption: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    method: Mapped[str] = mapped_column(String(12))
    path: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)

class ExploitResearch(Base):
    __tablename__ = "exploit_research"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    target_address: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(12))
    service_name: Mapped[str] = mapped_column(String(200))
    discovered_version: Mapped[str] = mapped_column(String(200), default="")
    discovery_evidence_type: Mapped[str] = mapped_column(String(40), default="manual")
    discovery_evidence: Mapped[str] = mapped_column(Text, default="")
    related_enumeration: Mapped[str] = mapped_column(Text, default="")
    cve: Mapped[str] = mapped_column(String(40), default="", index=True)
    exploit_db_id: Mapped[str] = mapped_column(String(40), default="", index=True)
    advisory_id: Mapped[str] = mapped_column(String(120), default="")
    title: Mapped[str] = mapped_column(String(300))
    affected_versions: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    authentication_required: Mapped[bool] = mapped_column(Boolean, default=False)
    required_privileges: Mapped[str] = mapped_column(String(200), default="")
    required_feature: Mapped[str] = mapped_column(Text, default="")
    required_endpoint: Mapped[str] = mapped_column(Text, default="")
    os_conditions: Mapped[str] = mapped_column(Text, default="")
    runtime_conditions: Mapped[str] = mapped_column(Text, default="")
    network_conditions: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    validation_status: Mapped[str] = mapped_column(String(30), default="unverified", index=True)
    execution_result: Mapped[str] = mapped_column(String(30), default="not_run", index=True)
    execution_command: Mapped[str] = mapped_column(Text, default="")
    reproduction_steps: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(160), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ExploitSource(Base):
    __tablename__ = "exploit_sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    research_id: Mapped[int] = mapped_column(
        ForeignKey("exploit_research.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300), default="")
    source_url: Mapped[str] = mapped_column(Text, default="")
    source_type: Mapped[str] = mapped_column(String(40), default="manual")
    author: Mapped[str] = mapped_column(String(200), default="")
    exploit_db_id: Mapped[str] = mapped_column(String(40), default="")
    platform: Mapped[str] = mapped_column(String(100), default="")
    exploit_type: Mapped[str] = mapped_column(String(100), default="")
    searchsploit_path: Mapped[str] = mapped_column(Text, default="")
    original_path: Mapped[str] = mapped_column(Text, default="")
    original_sha256: Mapped[str] = mapped_column(String(64), default="")
    working_path: Mapped[str] = mapped_column(Text, default="")
    working_sha256: Mapped[str] = mapped_column(String(64), default="")
    runtime: Mapped[str] = mapped_column(String(120), default="")
    libraries: Mapped[str] = mapped_column(Text, default="")
    run_conditions: Mapped[str] = mapped_column(Text, default="")
    raw_output: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ExploitModification(Base):
    __tablename__ = "exploit_modifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    research_id: Mapped[int] = mapped_column(
        ForeignKey("exploit_research.id", ondelete="CASCADE"), index=True)
    variable_name: Mapped[str] = mapped_column(String(120))
    original_value: Mapped[str] = mapped_column(Text, default="")
    modified_value: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ExploitExecutionRecord(Base):
    __tablename__ = "exploit_execution_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    research_id: Mapped[int] = mapped_column(
        ForeignKey("exploit_research.id", ondelete="CASCADE"), index=True)
    terminal_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("interactive_sessions.id"), nullable=True)
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id"), nullable=True)
    command: Mapped[str] = mapped_column(Text)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout_path: Mapped[str] = mapped_column(Text, default="")
    stderr_path: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[str] = mapped_column(String(30), default="not_run")
    related_session_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

class ExploitLocalRun(Base):
    __tablename__ = "exploit_local_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    research_id: Mapped[int] = mapped_column(
        ForeignKey("exploit_research.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("exploit_sources.id", ondelete="CASCADE"), index=True)
    request_key: Mapped[str] = mapped_column(String(120), unique=True)
    approval_token_hash: Mapped[str] = mapped_column(String(64))
    file_name: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(Text)
    file_sha256: Mapped[str] = mapped_column(String(64))
    runtime: Mapped[str] = mapped_column(String(30))
    argv_json: Mapped[str] = mapped_column(Text)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="prepared", index=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout_path: Mapped[str] = mapped_column(Text, default="")
    stderr_path: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False)
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id"), nullable=True)
    user_result: Mapped[str] = mapped_column(String(30), default="not_run")
    user_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookTemplate(Base):
    __tablename__ = "runbook_templates"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    service_names: Mapped[str] = mapped_column(Text, default="[]")
    ports: Mapped[str] = mapped_column(Text, default="[]")
    origin: Mapped[str] = mapped_column(String(20), default="user")
    builtin_key: Mapped[str | None] = mapped_column(String(120), nullable=True, unique=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookTemplateVersion(Base):
    __tablename__ = "runbook_template_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("runbook_templates.id"))
    version: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    service_names: Mapped[str] = mapped_column(Text, default="[]")
    ports: Mapped[str] = mapped_column(Text, default="[]")
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookStepTemplate(Base):
    __tablename__ = "runbook_step_templates"
    id: Mapped[int] = mapped_column(primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("runbook_template_versions.id"))
    position: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    command_refs: Mapped[str] = mapped_column(Text, default="[]")
    expected_observations: Mapped[str] = mapped_column(Text, default="[]")
    condition: Mapped[str] = mapped_column(Text, default="{}")
    guidance: Mapped[str] = mapped_column(Text, default="{}")
    node_key: Mapped[str] = mapped_column(String(120), default="")
    node_type: Mapped[str] = mapped_column(String(32), default="manual_check")
    transitions: Mapped[str] = mapped_column(Text, default="[]")
    error_policy: Mapped[str] = mapped_column(Text, default="{}")
    approval: Mapped[str] = mapped_column(Text, default="{}")


class RunbookInstance(Base):
    __tablename__ = "runbook_instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("runbook_template_versions.id"))
    template_name: Mapped[str] = mapped_column(String(160))
    target_name: Mapped[str] = mapped_column(String(120))
    service_name: Mapped[str] = mapped_column(String(80), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookStepInstance(Base):
    __tablename__ = "runbook_step_instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("runbook_instances.id"))
    source_step_id: Mapped[int] = mapped_column(ForeignKey("runbook_step_templates.id"))
    position: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    command_refs: Mapped[str] = mapped_column(Text, default="[]")
    expected_observations: Mapped[str] = mapped_column(Text, default="[]")
    condition: Mapped[str] = mapped_column(Text, default="{}")
    guidance: Mapped[str] = mapped_column(Text, default="{}")
    node_key: Mapped[str] = mapped_column(String(120), default="")
    node_type: Mapped[str] = mapped_column(String(32), default="manual_check")
    transitions: Mapped[str] = mapped_column(Text, default="[]")
    error_policy: Mapped[str] = mapped_column(Text, default="{}")
    approval: Mapped[str] = mapped_column(Text, default="{}")
    activation: Mapped[str] = mapped_column(String(24), default="waiting")
    decision_trace: Mapped[str] = mapped_column(Text, default="[]")
    approval_status: Mapped[str] = mapped_column(String(24), default="not_required")
    approval_reason: Mapped[str] = mapped_column(Text, default="")
    approved_by: Mapped[str] = mapped_column(String(160), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="not_started")
    outcome: Mapped[str] = mapped_column(String(24), default="unknown")
    assessment: Mapped[str] = mapped_column(Text, default="{}")
    result: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    status_reason: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timer_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    elapsed_seconds: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookStepEvidence(Base):
    __tablename__ = "runbook_step_evidence"
    step_id: Mapped[int] = mapped_column(
        ForeignKey("runbook_step_instances.id"), primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookStepExecution(Base):
    __tablename__ = "runbook_step_executions"
    step_id: Mapped[int] = mapped_column(
        ForeignKey("runbook_step_instances.id"), primary_key=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("executions.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookActivityEvent(Base):
    __tablename__ = "runbook_activity_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("runbook_instances.id"))
    step_id: Mapped[int | None] = mapped_column(
        ForeignKey("runbook_step_instances.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(40))
    details: Mapped[str] = mapped_column(Text, default="{}")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(200))
    secret_kind: Mapped[str] = mapped_column(String(30), default="password")
    secret_hint: Mapped[str] = mapped_column(String(200), default="")
    # Opt-in plaintext secret for local single-user reuse (auto-filling command
    # generation). Empty keeps the conservative hint-only behaviour.
    secret: Mapped[str] = mapped_column(Text, default="")
    source_kind: Mapped[str] = mapped_column(String(40), default="manual")
    source_detail: Mapped[str] = mapped_column(Text, default="")
    domain: Mapped[str] = mapped_column(String(253), default="")
    service_names: Mapped[str] = mapped_column(Text, default="[]")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookStepCredential(Base):
    __tablename__ = "runbook_step_credentials"
    step_id: Mapped[int] = mapped_column(
        ForeignKey("runbook_step_instances.id"), primary_key=True)
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credentials.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookObservation(Base):
    __tablename__ = "runbook_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    step_id: Mapped[int] = mapped_column(ForeignKey("runbook_step_instances.id"))
    title: Mapped[str] = mapped_column(String(240))
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunbookRecommendationDismissal(Base):
    __tablename__ = "runbook_recommendation_dismissals"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    version_id: Mapped[int] = mapped_column(ForeignKey("runbook_template_versions.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    dismissed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
