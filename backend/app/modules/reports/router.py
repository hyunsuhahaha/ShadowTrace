import base64
import html
import json
from pathlib import Path
import markdown as markdown_lib
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from weasyprint import HTML
from ...database import get_db
from ...models import Evidence, Project, Report
from ...schemas import ReportIn, ReportOut
from ...time import utcnow

router = APIRouter(prefix="/api/reports", tags=["Reports"])
OSCP_TEMPLATE = """# OSCP Penetration Test Report

## Executive Summary

Write your own summary and assessment.

## Scope

Record the authorized targets and limitations.

## Methodology

Document the manual methodology used during the examination.

## Findings

### Target

#### Finding title

**Observation**

**Impact (user-authored)**

**Reproduction steps**

**Evidence**

## Additional Information

## Evidence Index
"""


def need(db: Session, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row


def values(body: ReportIn) -> dict:
    result = body.model_dump()
    result["evidence_links"] = json.dumps(
        result["evidence_links"], ensure_ascii=False)
    if result["template"] == "oscp" and not result["markdown"]:
        result["markdown"] = OSCP_TEMPLATE
    return result


@router.get("", response_model=list[ReportOut])
def reports(project_id: int, db: Session = Depends(get_db)):
    return db.scalars(select(Report).where(
        Report.project_id == project_id).order_by(Report.id.desc())).all()


@router.post("", response_model=ReportOut, status_code=201)
def create_report(body: ReportIn, db: Session = Depends(get_db)):
    need(db, Project, body.project_id)
    row = Report(**values(body))
    db.add(row); db.commit(); db.refresh(row)
    return row


@router.put("/{ident}", response_model=ReportOut)
def update_report(ident: int, body: ReportIn,
                  db: Session = Depends(get_db)):
    row = need(db, Report, ident)
    if row.project_id != body.project_id:
        raise HTTPException(400, "Project cannot be changed")
    for key, value in values(body).items():
        setattr(row, key, value)
    row.updated_at = utcnow()
    db.commit(); db.refresh(row)
    return row


def render_report(db: Session, row: Report) -> str:
    links = json.loads(row.evidence_links)
    evidence_rows = []
    sensitive = []
    for link in links:
        evidence = need(db, Evidence, int(link["id"]))
        if evidence.project_id != row.project_id:
            raise HTTPException(400, "Linked evidence belongs to another project")
        if evidence.sensitivity != "normal":
            sensitive.append(evidence.id)
        caption = html.escape(str(link.get("caption", evidence.title)))
        preview = ""
        path = Path(evidence.file_path)
        if evidence.kind == "screenshot" and path.is_file() and path.stat().st_size <= 10_000_000:
            encoded = base64.b64encode(path.read_bytes()).decode()
            preview = f'<img src="data:image/png;base64,{encoded}" alt="{caption}">'
        evidence_rows.append(
            f"<article><h3>Evidence #{evidence.id}: {html.escape(evidence.title)}</h3>"
            f"{preview}<p>{caption}</p><code>SHA-256: {evidence.sha256}</code></article>")
    if sensitive and not row.sensitivity_reviewed:
        raise HTTPException(
            409, f"Sensitive evidence review required for IDs: {sensitive}")
    safe_markdown = html.escape(row.markdown)
    content = markdown_lib.markdown(
        safe_markdown, extensions=["fenced_code", "tables"])
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(row.title)}</title>
<style>body{{font:11pt sans-serif;max-width:900px;margin:40px auto;line-height:1.5}}
code,pre{{font-family:monospace;background:#f2f2f2}}pre{{padding:12px;white-space:pre-wrap}}
img{{max-width:100%;max-height:700px}}article{{break-inside:avoid;border-top:1px solid #bbb;margin-top:20px}}
table{{border-collapse:collapse}}td,th{{border:1px solid #aaa;padding:5px}}</style></head>
<body><h1>{html.escape(row.title)}</h1>{content}<section><h2>Evidence Index</h2>{''.join(evidence_rows)}</section></body></html>"""


@router.get("/{ident}/export")
def export_report(ident: int, format: str = "html",
                  db: Session = Depends(get_db)):
    row = need(db, Report, ident)
    document = render_report(db, row)
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_"
                        for c in row.title).strip("._") or f"report-{row.id}"
    if format == "html":
        return Response(document, media_type="text/html",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{safe_name}.html"'})
    if format == "pdf":
        pdf = HTML(string=document).write_pdf()
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{safe_name}.pdf"'})
    raise HTTPException(400, "Format must be html or pdf")
