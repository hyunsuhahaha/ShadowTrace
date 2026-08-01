from __future__ import annotations
import html
import base64
import binascii
import hashlib
import json
import math
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
import yaml
from ...database import get_db
from ...config import WORKSPACE_DIR
from ...models import (Evidence, EvidenceImageEdit, Finding, FindingAsset, FindingEvidence,
    FindingRetest, FindingTemplate, Project, Service, Target)
from ...schemas import FindingIn, FindingRetestIn, FindingTemplateIn, ImageEditIn
from ...time import utcnow

router = APIRouter(prefix="/api", tags=["Findings"])
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
WEIGHTS = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}

def need(db, model, ident):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row

def cvss31(vector: str) -> tuple[float, str]:
    if not vector:
        return 0.0, "Informational"
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        raise HTTPException(422, "Only CVSS:3.1 vectors are supported")
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            raise HTTPException(422, "Invalid CVSS vector")
        key, value = part.split(":", 1)
        if key in metrics:
            raise HTTPException(422, f"Duplicate CVSS metric: {key}")
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(metrics) != required:
        raise HTTPException(422, "CVSS vector must contain AV, AC, PR, UI, S, C, I and A")
    weights = {
        "AV": {"N": .85, "A": .62, "L": .55, "P": .2},
        "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62},
        "C": {"H": .56, "L": .22, "N": 0}, "I": {"H": .56, "L": .22, "N": 0},
        "A": {"H": .56, "L": .22, "N": 0},
    }
    try:
        scope = metrics["S"]
        if scope not in ("U", "C"):
            raise KeyError
        pr = ({"N": .85, "L": .62, "H": .27} if scope == "U"
              else {"N": .85, "L": .68, "H": .5})[metrics["PR"]]
        exploit = 8.22 * weights["AV"][metrics["AV"]] * weights["AC"][metrics["AC"]] * pr * weights["UI"][metrics["UI"]]
        isc = 1 - math.prod(1 - weights[x][metrics[x]] for x in ("C", "I", "A"))
    except KeyError:
        raise HTTPException(422, "Invalid CVSS metric value")
    impact = 6.42 * isc if scope == "U" else 7.52 * (isc - .029) - 3.25 * (isc - .02) ** 15
    raw = 0 if impact <= 0 else (min(impact + exploit, 10) if scope == "U"
        else min(1.08 * (impact + exploit), 10))
    score = math.ceil(raw * 10 - 1e-9) / 10
    severity = ("Critical" if score >= 9 else "High" if score >= 7
                else "Medium" if score >= 4 else "Low" if score > 0 else "Informational")
    return score, severity

def scope(db: Session, project_id: int, target_id: int | None, service_id: int | None):
    need(db, Project, project_id)
    if target_id:
        target = need(db, Target, target_id)
        if target.project_id != project_id:
            raise HTTPException(400, "Target belongs to another project")
    if service_id:
        service = need(db, Service, service_id)
        if not target_id or service.target_id != target_id:
            raise HTTPException(400, "Service belongs to another target")

def template_dict(row):
    return {key: getattr(row, key) for key in ("title", "category", "severity",
        "cvss_vector", "description", "impact", "recommendation", "references",
        "cwe", "cve", "mitre_attack", "tags")}

def serialize_finding(db, row, profile=None):
    if profile == "client" and row.disclosure == "INTERNAL":
        return None
    links = db.scalars(select(FindingEvidence).where(
        FindingEvidence.finding_id == row.id).order_by(FindingEvidence.display_order, FindingEvidence.id)).all()
    evidence = []
    for link in links:
        if profile == "client" and not link.include_client: continue
        if profile == "internal" and not link.include_internal: continue
        source = db.get(Evidence, link.evidence_id) if link.evidence_id else None
        if source and source.project_id != row.project_id: continue
        if profile == "client" and source and source.sensitivity != "normal": continue
        evidence.append({"id": link.id, "evidence_id": link.evidence_id,
            "title": source.title if source else "[deleted evidence]",
            "kind": source.kind if source else "", "caption": link.caption,
            "display_order": link.display_order, "include_client": link.include_client,
            "include_internal": link.include_internal, "is_primary": link.is_primary,
            "phase": link.phase})
    data = {c.name: getattr(row, c.name) for c in Finding.__table__.columns}
    data["references"], data["tags"] = json.loads(row.references), json.loads(row.tags)
    data["evidence"] = evidence
    assets = db.scalars(select(FindingAsset).where(
        FindingAsset.finding_id == row.id).order_by(FindingAsset.id)).all()
    data["target_ids"] = list(dict.fromkeys(
        [item.target_id for item in assets] + ([row.target_id] if row.target_id else [])))
    data["service_ids"] = list(dict.fromkeys(
        [item.service_id for item in assets if item.service_id]
        + ([row.service_id] if row.service_id else [])))
    data["retests"] = []
    for item in db.scalars(select(FindingRetest).where(
            FindingRetest.finding_id == row.id).order_by(
            FindingRetest.tested_at.desc(), FindingRetest.id.desc())).all():
        retest = {c.name: getattr(item, c.name) for c in FindingRetest.__table__.columns}
        retest["before_evidence_ids"] = json.loads(item.before_evidence_ids)
        retest["after_evidence_ids"] = json.loads(item.after_evidence_ids)
        data["retests"].append(retest)
    if profile == "client":
        data.pop("internal_notes", None)
        for retest in data["retests"]:
            retest.pop("notes", None)
    return data

def finding_values(body):
    score, severity = cvss31(body.cvss_vector)
    if body.final_risk != severity and not body.risk_override_reason.strip():
        raise HTTPException(422, "A risk override reason is required when final risk differs from CVSS severity")
    values = body.model_dump(exclude={"evidence", "target_ids", "service_ids"})
    values.update(cvss_score=str(score), severity=severity,
        references=json.dumps(body.references, ensure_ascii=False),
        tags=json.dumps(body.tags, ensure_ascii=False))
    return values

def replace_evidence(db, row, links):
    db.execute(delete(FindingEvidence).where(FindingEvidence.finding_id == row.id))
    primary = sum(item.is_primary for item in links)
    if primary > 1:
        raise HTTPException(422, "Only one primary evidence item is allowed")
    for item in links:
        evidence = need(db, Evidence, item.evidence_id)
        if evidence.project_id != row.project_id:
            raise HTTPException(400, "Evidence belongs to another project")
        db.add(FindingEvidence(finding_id=row.id, **item.model_dump()))

def replace_assets(db, row, body):
    db.execute(delete(FindingAsset).where(FindingAsset.finding_id == row.id))
    target_ids = list(dict.fromkeys(body.target_ids or (
        [body.target_id] if body.target_id else [])))
    service_ids = list(dict.fromkeys(body.service_ids or (
        [body.service_id] if body.service_id else [])))
    targets = {ident: need(db, Target, ident) for ident in target_ids}
    if any(target.project_id != row.project_id for target in targets.values()):
        raise HTTPException(400, "Target belongs to another project")
    services = {ident: need(db, Service, ident) for ident in service_ids}
    for service in services.values():
        target = need(db, Target, service.target_id)
        if target.project_id != row.project_id:
            raise HTTPException(400, "Service belongs to another project")
        targets[target.id] = target
    for target_id in targets:
        linked = [item.id for item in services.values() if item.target_id == target_id]
        if linked:
            for service_id in linked:
                db.add(FindingAsset(finding_id=row.id, target_id=target_id,
                                    service_id=service_id))
        else:
            db.add(FindingAsset(finding_id=row.id, target_id=target_id))

@router.get("/cvss")
def calculate_cvss(vector: str):
    score, severity = cvss31(vector)
    return {"version": "3.1", "vector": vector, "score": score, "severity": severity}

@router.get("/finding-templates")
def templates(q: str = "", category: str = "", tag: str = "", db: Session = Depends(get_db)):
    stmt = select(FindingTemplate).order_by(FindingTemplate.title)
    if q: stmt = stmt.where(FindingTemplate.title.ilike(f"%{q}%"))
    if category: stmt = stmt.where(FindingTemplate.category == category)
    if tag: stmt = stmt.where(FindingTemplate.tags.ilike(f'%"{tag}"%'))
    return [template_dict(x) | {"id": x.id, "use_count": x.use_count, "last_used_at": x.last_used_at} for x in db.scalars(stmt).all()]

@router.post("/finding-templates", status_code=201)
def create_template(body: FindingTemplateIn, db: Session = Depends(get_db)):
    if body.cvss_vector: cvss31(body.cvss_vector)
    row = FindingTemplate(**body.model_dump(exclude={"references", "mitre_attack", "tags"}),
        references=json.dumps(body.references), mitre_attack=json.dumps(body.mitre_attack), tags=json.dumps(body.tags))
    db.add(row); db.commit(); db.refresh(row)
    return template_dict(row) | {"id": row.id, "use_count": row.use_count}

@router.put("/finding-templates/{ident}")
def update_template(ident: int, body: FindingTemplateIn, db: Session = Depends(get_db)):
    row = need(db, FindingTemplate, ident)
    values = body.model_dump()
    for key in ("references", "mitre_attack", "tags"): values[key] = json.dumps(values[key])
    for key, value in values.items(): setattr(row, key, value)
    row.updated_at = utcnow(); db.commit()
    return template_dict(row) | {"id": row.id, "use_count": row.use_count}

@router.post("/finding-templates/{ident}/clone", status_code=201)
def clone_template(ident: int, db: Session = Depends(get_db)):
    source = need(db, FindingTemplate, ident); values = template_dict(source)
    values["title"] += " (Copy)"
    row = FindingTemplate(**values); db.add(row); db.commit(); db.refresh(row)
    return template_dict(row) | {"id": row.id, "use_count": 0}

@router.delete("/finding-templates/{ident}", status_code=204)
def delete_template(ident: int, db: Session = Depends(get_db)):
    db.delete(need(db, FindingTemplate, ident)); db.commit()

@router.get("/finding-templates/export")
def export_templates(format: str = "json", db: Session = Depends(get_db)):
    data = [template_dict(x) for x in db.scalars(select(FindingTemplate)).all()]
    if format == "yaml":
        return Response(yaml.safe_dump(data, allow_unicode=True), media_type="application/yaml")
    return data

@router.post("/finding-templates/import")
def import_templates(items: list[FindingTemplateIn], duplicate: str = "skip", db: Session = Depends(get_db)):
    if duplicate not in ("skip", "replace", "copy"): raise HTTPException(400, "Invalid duplicate strategy")
    imported = 0
    for body in items:
        existing = db.scalar(select(FindingTemplate).where(func.lower(FindingTemplate.title) == body.title.lower()))
        if existing and duplicate == "skip": continue
        if existing and duplicate == "replace": db.delete(existing); db.flush()
        title = body.title if not existing or duplicate != "copy" else body.title + " (Imported)"
        values = body.model_dump(); values["title"] = title
        for key in ("references", "mitre_attack", "tags"): values[key] = json.dumps(values[key])
        db.add(FindingTemplate(**values)); imported += 1
    db.commit(); return {"imported": imported}

@router.post("/finding-templates/{ident}/apply", status_code=201)
def apply_template(ident: int, project_id: int, target_id: int | None = None,
                   service_id: int | None = None, db: Session = Depends(get_db)):
    scope(db, project_id, target_id, service_id); template = need(db, FindingTemplate, ident)
    snapshot = template_dict(template); score, severity = cvss31(template.cvss_vector)
    row = Finding(project_id=project_id, target_id=target_id, service_id=service_id,
        template_id=template.id, title=template.title, category=template.category,
        severity=severity, cvss_vector=template.cvss_vector, cvss_score=str(score),
        final_risk=severity, description=template.description, business_impact=template.impact,
        recommendation=template.recommendation, references=template.references, tags=template.tags,
        template_snapshot=json.dumps(snapshot, ensure_ascii=False))
    template.use_count += 1; template.last_used_at = utcnow()
    db.add(row); db.flush()
    if target_id:
        db.add(FindingAsset(finding_id=row.id, target_id=target_id,
                            service_id=service_id))
    db.commit(); db.refresh(row)
    return serialize_finding(db, row)

@router.get("/findings")
def findings(project_id: int, q: str = "", severity: str = "", status: str = "",
             target_id: int | None = None, service_id: int | None = None,
             tag: str = "", db: Session = Depends(get_db)):
    stmt = select(Finding).where(Finding.project_id == project_id)
    if q: stmt = stmt.where(Finding.title.ilike(f"%{q}%"))
    if severity: stmt = stmt.where(Finding.final_risk == severity)
    if status: stmt = stmt.where(Finding.status == status)
    if target_id: stmt = stmt.where(Finding.target_id == target_id)
    if service_id: stmt = stmt.where(Finding.service_id == service_id)
    if tag: stmt = stmt.where(Finding.tags.ilike(f'%"{tag}"%'))
    rows = db.scalars(stmt).all()
    asset_counts = dict(db.execute(select(FindingAsset.finding_id,
        func.count(FindingAsset.id)).group_by(FindingAsset.finding_id)).all())
    rows.sort(key=lambda x: (-WEIGHTS[x.final_risk], -float(x.cvss_score),
        -x.sort_priority, -asset_counts.get(x.id, 0), x.id))
    return [serialize_finding(db, x) for x in rows]

@router.post("/findings", status_code=201)
def create_finding(body: FindingIn, db: Session = Depends(get_db)):
    scope(db, body.project_id, body.target_id, body.service_id)
    for link in body.evidence:
        if need(db, Evidence, link.evidence_id).project_id != body.project_id:
            raise HTTPException(400, "Evidence belongs to another project")
    row = Finding(**finding_values(body)); db.add(row); db.flush()
    replace_evidence(db, row, body.evidence); replace_assets(db, row, body)
    db.commit(); db.refresh(row)
    return serialize_finding(db, row)

@router.get("/findings/{ident}")
def get_finding(ident: int, profile: str | None = None, db: Session = Depends(get_db)):
    if profile not in (None, "client", "internal"): raise HTTPException(400, "Invalid profile")
    data = serialize_finding(db, need(db, Finding, ident), profile)
    if data is None: raise HTTPException(404, "Finding is not available in this profile")
    return data

@router.put("/findings/{ident}")
def update_finding(ident: int, body: FindingIn, db: Session = Depends(get_db)):
    row = need(db, Finding, ident)
    if row.project_id != body.project_id: raise HTTPException(400, "Project cannot be changed")
    scope(db, body.project_id, body.target_id, body.service_id)
    for key, value in finding_values(body).items(): setattr(row, key, value)
    row.updated_at = utcnow(); replace_evidence(db, row, body.evidence)
    replace_assets(db, row, body)
    db.commit(); return serialize_finding(db, row)

@router.delete("/findings/{ident}", status_code=204)
def delete_finding(ident: int, db: Session = Depends(get_db)):
    db.delete(need(db, Finding, ident)); db.commit()

@router.post("/findings/bulk-status")
def bulk_status(project_id: int, ids: list[int], status: str, db: Session = Depends(get_db)):
    allowed = {"Draft", "Confirmed", "Needs Review", "Remediated", "Accepted Risk", "False Positive"}
    if status not in allowed or not ids or len(ids) > 500: raise HTTPException(422, "Invalid bulk update")
    rows = db.scalars(select(Finding).where(Finding.id.in_(ids), Finding.project_id == project_id)).all()
    if len(rows) != len(set(ids)): raise HTTPException(404, "Finding not found in project")
    for row in rows: row.status = status; row.updated_at = utcnow()
    db.commit(); return {"updated": len(rows)}

@router.post("/findings/{ident}/retests", status_code=201)
def add_retest(ident: int, body: FindingRetestIn, db: Session = Depends(get_db)):
    row = need(db, Finding, ident)
    ids = body.before_evidence_ids + body.after_evidence_ids
    if ids:
        valid = db.scalar(select(func.count()).select_from(Evidence).where(Evidence.id.in_(ids), Evidence.project_id == row.project_id))
        if valid != len(set(ids)): raise HTTPException(400, "Evidence belongs to another project")
    retest = FindingRetest(finding_id=row.id, tester=body.tester, result=body.result,
        remediated=body.remediated, notes=body.notes,
        before_evidence_ids=json.dumps(body.before_evidence_ids),
        after_evidence_ids=json.dumps(body.after_evidence_ids))
    row.retested_at = utcnow(); row.retest_result = body.result
    if body.remediated: row.status = "Remediated"
    db.add(retest); db.commit(); db.refresh(retest)
    return {c.name: getattr(retest, c.name) for c in FindingRetest.__table__.columns}

@router.get("/projects/{project_id}/finding-summary")
def summary(project_id: int, profile: str = "client", db: Session = Depends(get_db)):
    need(db, Project, project_id)
    rows = db.scalars(select(Finding).where(Finding.project_id == project_id)).all()
    if profile == "client": rows = [x for x in rows if x.disclosure != "INTERNAL"]
    counts = {x: sum(f.final_risk == x for f in rows) for x in SEVERITIES}
    finding_ids = [x.id for x in rows]
    assets = db.scalars(select(FindingAsset).where(
        FindingAsset.finding_id.in_(finding_ids))).all() if finding_ids else []
    targets = len({x.target_id for x in assets}
        | {x.target_id for x in rows if x.target_id})
    services = len({x.service_id for x in assets if x.service_id}
        | {x.service_id for x in rows if x.service_id})
    open_count = sum(x.status not in ("Remediated", "False Positive") for x in rows)
    priority = sorted(rows, key=lambda x: (-WEIGHTS[x.final_risk], -float(x.cvss_score), -x.sort_priority, x.id))[:5]
    text = (f"This assessment identified {len(rows)} findings across {targets} target(s) and "
            f"{services} service(s). {open_count} finding(s) require further action.")
    return {"total": len(rows), "severity": counts, "targets": targets, "services": services,
        "remediated": len(rows) - open_count, "open": open_count,
        "highest": priority[0].title if priority else None,
        "priority": [{"id": x.id, "title": x.title, "risk": x.final_risk} for x in priority],
        "generated_summary": text}

@router.post("/evidence/{ident}/image-edits", status_code=201)
def save_image_edit(ident: int, body: ImageEditIn, db: Session = Depends(get_db)):
    evidence = need(db, Evidence, ident)
    if evidence.kind != "screenshot" or not evidence.sha256:
        raise HTTPException(422, "Image edits require immutable screenshot evidence")
    version = (db.scalar(select(func.max(EvidenceImageEdit.version)).where(
        EvidenceImageEdit.evidence_id == ident)) or 0) + 1
    rendered_path = rendered_sha256 = ""
    if body.rendered_png_base64:
        try:
            content = base64.b64decode(body.rendered_png_base64, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(422, "Invalid rendered PNG")
        if len(content) > 10_000_000 or not content.startswith(b"\x89PNG\r\n\x1a\n"):
            raise HTTPException(422, "Rendered image must be a PNG under 10 MB")
        source = Path(evidence.file_path).resolve()
        root = WORKSPACE_DIR.resolve()
        if (not evidence.file_path or root not in source.parents
                or not source.is_file() or source.is_symlink()):
            raise HTTPException(410, "Original evidence is unavailable")
        folder = source.parent / "edits"
        folder.mkdir(exist_ok=True)
        if folder.is_symlink() or root not in folder.resolve().parents:
            raise HTTPException(400, "Unsafe image edit path")
        path = folder / f"v{version}.png"
        path.write_bytes(content)
        rendered_path = str(path)
        rendered_sha256 = hashlib.sha256(content).hexdigest()
    row = EvidenceImageEdit(evidence_id=ident, version=version,
        operations=json.dumps(body.operations), original_sha256=evidence.sha256,
        rendered_path=rendered_path, rendered_sha256=rendered_sha256,
        caption=body.caption)
    db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id, "evidence_id": ident, "version": version,
        "operations": body.operations, "caption": row.caption,
        "original_sha256": row.original_sha256,
        "rendered_path": row.rendered_path,
        "rendered_sha256": row.rendered_sha256}

@router.get("/evidence/{ident}/image-edits")
def image_edits(ident: int, db: Session = Depends(get_db)):
    need(db, Evidence, ident)
    rows = db.scalars(select(EvidenceImageEdit).where(
        EvidenceImageEdit.evidence_id == ident).order_by(
        EvidenceImageEdit.version.desc())).all()
    return [{"id": row.id, "version": row.version,
        "operations": json.loads(row.operations), "caption": row.caption,
        "original_sha256": row.original_sha256,
        "rendered_sha256": row.rendered_sha256,
        "created_at": row.created_at} for row in rows]
