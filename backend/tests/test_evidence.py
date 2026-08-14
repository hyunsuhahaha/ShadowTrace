import asyncio
import io
import json
import tempfile
import zipfile
import pytest
from fastapi import HTTPException, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Evidence, Finding, FindingEvidence, Project, Target
from app.modules.evidence.router import (evidence_archive, evidence_preview,
    export_evidence, extract_archive_entry, upload_evidence)
from app.schemas import ArchiveExtractIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_evidence_hash_duplicate_and_zip_manifest(tmp_path, monkeypatch):
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()

    async def upload(title):
        uploaded = tempfile.SpooledTemporaryFile()
        uploaded.write(b"proof")
        uploaded.seek(0)
        return await upload_evidence(
            project_id=project.id, target_id=target.id, title=title,
            kind="flag", description="", service_id=None,
            source_type="upload", source_id=None, sensitivity="sensitive",
            include_report=True,
            file=UploadFile(filename="proof.txt", file=uploaded),
            db=db)

    first = asyncio.run(upload("First"))
    second = asyncio.run(upload("Duplicate"))
    assert first.sha256 == second.sha256
    assert second.duplicate_of == first.id
    response = export_evidence([first.id, second.id], db)
    with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert len(manifest) == 2
        assert any(name.endswith("proof.txt") for name in archive.namelist())


def test_text_evidence_preview_is_readable_and_bounded(tmp_path, monkeypatch):
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(b"PORT   STATE SERVICE\n80/tcp open  http\n")
    uploaded.seek(0)
    row = asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="Nmap stdout",
        kind="command_output", description="", service_id=None,
        source_type="scan", source_id=9, sensitivity="normal",
        include_report=False, file=UploadFile(filename="stdout.txt", file=uploaded), db=db))

    preview = evidence_preview(row.id, db)

    assert preview == {"content": "PORT   STATE SERVICE\n80/tcp open  http\n",
                       "truncated": False, "language": "text"}


def _zip_evidence(db, project, target):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt", "loot")
        archive.writestr("logs/", "")  # a bare directory entry must be skipped, not listed
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(buffer.getvalue())
    uploaded.seek(0)
    return asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="파일 다운로드: backup.zip",
        kind="attachment", description="", service_id=None,
        source_type="interactive_session", source_id=1, sensitivity="normal",
        include_report=False, file=UploadFile(filename="backup.zip", file=uploaded), db=db))


def test_evidence_archive_lists_zip_entries_skipping_folders(tmp_path, monkeypatch):
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _zip_evidence(db, project, target)

    assert evidence_archive(row.id, db) == {
        "entries": [{"name": "notes.txt", "size": 4, "encrypted": False}]}


def test_extract_archive_entry_promotes_one_member_as_its_own_finding(tmp_path, monkeypatch):
    # Same idea as promote-download/promote-file, one level into an archive
    # instead of a session's cwd or a post-exploitation file tree.
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _zip_evidence(db, project, target)

    result = extract_archive_entry(row.id, ArchiveExtractIn(entry="notes.txt"), db=db)

    finding = db.get(Finding, result["finding_id"])
    assert finding is not None and finding.status == "Draft" and finding.target_id == target.id
    evidence = db.get(Evidence, result["evidence_id"])
    assert evidence is not None and evidence.kind == "attachment"
    assert evidence.original_name == "notes.txt"
    from pathlib import Path as _Path
    assert _Path(evidence.file_path).read_bytes() == b"loot"
    link = db.query(FindingEvidence).filter_by(finding_id=finding.id).one()
    assert link.evidence_id == evidence.id and link.is_primary is True


def test_extract_archive_entry_rejects_an_entry_that_is_not_in_the_zip(tmp_path, monkeypatch):
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _zip_evidence(db, project, target)

    with pytest.raises(HTTPException) as exc:
        extract_archive_entry(row.id, ArchiveExtractIn(entry="../../etc/passwd"), db=db)
    assert exc.value.status_code == 404


def test_evidence_archive_rejects_a_non_zip_file(tmp_path, monkeypatch):
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(b"not a zip")
    uploaded.seek(0)
    row = asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="notes",
        kind="attachment", description="", service_id=None,
        source_type="upload", source_id=None, sensitivity="normal",
        include_report=False, file=UploadFile(filename="notes.zip", file=uploaded), db=db))

    with pytest.raises(HTTPException) as exc:
        evidence_archive(row.id, db)
    assert exc.value.status_code == 415


def test_extract_archive_entry_sends_a_password_protected_member_to_hash_cracking_instead_of_500ing(
        tmp_path, monkeypatch):
    # zipfile can list a ZipCrypto-encrypted member's name/size without its
    # password, but .read() on it raises a bare RuntimeError -- this used to
    # surface as an unhandled 500 (confirmed live against a real vulnerable
    # app's protected source zip). It should read as a clear next step
    # instead, since this app already has zip2john (HashCrackingWorkspace)
    # for exactly this.
    import subprocess
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    secret_txt = tmp_path / "secret.txt"
    secret_txt.write_text("root:hunter2")
    zip_path = tmp_path / "protected.zip"
    subprocess.run(["zip", "-j", "-P", "hunter2", str(zip_path), str(secret_txt)],
                   check=True, capture_output=True)
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(zip_path.read_bytes())
    uploaded.seek(0)
    row = asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="파일 다운로드: protected.zip",
        kind="attachment", description="", service_id=None,
        source_type="interactive_session", source_id=1, sensitivity="normal",
        include_report=False, file=UploadFile(filename="protected.zip", file=uploaded), db=db))

    listing = evidence_archive(row.id, db)
    assert listing == {"entries": [{"name": "secret.txt", "size": 12, "encrypted": True}]}

    with pytest.raises(HTTPException) as exc:
        extract_archive_entry(row.id, ArchiveExtractIn(entry="secret.txt"), db=db)
    assert exc.value.status_code == 422
    assert "zip2john" in exc.value.detail
