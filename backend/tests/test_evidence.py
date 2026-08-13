import asyncio
import io
import json
import tempfile
import zipfile
from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Project, Target
from app.modules.evidence.router import evidence_preview, export_evidence, upload_evidence


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
