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
from app.modules.evidence.router import export_evidence, upload_evidence


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
