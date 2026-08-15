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
from app.models import Evidence, Finding, FindingEvidence, GraphEdge, Project, Target
from app.modules.evidence.router import (evidence_archive, evidence_preview,
    evidence_zip2john, export_evidence, extract_archive_entry, upload_evidence)
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


def test_downloaded_web_app_source_is_also_previewable_as_text(tmp_path, monkeypatch):
    # A .php/.py/.env/... pulled off a target (LFI, exposed .git, anon FTP,
    # ...) is plain text same as any command-output extension already on
    # this list -- reading it for hardcoded DB creds or a password hash is
    # standard whitebox review, previously blocked by nothing but a
    # narrower extension allowlist.
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(b"<?php $db = new mysqli('localhost','root','P@ssw0rd123'); ?>")
    uploaded.seek(0)
    row = asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="dashboard.php",
        kind="attachment", description="", service_id=None,
        source_type="execution", source_id=90, sensitivity="normal",
        include_report=False, file=UploadFile(filename="dashboard.php", file=uploaded), db=db))

    preview = evidence_preview(row.id, db)

    assert "P@ssw0rd123" in preview["content"]


def test_extracted_css_is_previewable_too(tmp_path, monkeypatch):
    # Confirmed live: .css was missing from TEXT_EXTENSIONS entirely, so an
    # archive-extracted style.css always 415'd -- the Inspector's own
    # graceful isError handling then just quietly hid the whole preview
    # section instead of a visible error, which read as "this file has no
    # content" rather than the actual bug.
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(b"body { background: #000; }")
    uploaded.seek(0)
    row = asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="style.css",
        kind="attachment", description="", service_id=None,
        source_type="archive_extract", source_id=1, sensitivity="normal",
        include_report=False, file=UploadFile(filename="style.css", file=uploaded), db=db))

    preview = evidence_preview(row.id, db)

    assert "background: #000" in preview["content"]


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


def test_extract_archive_entry_attaches_the_finding_to_the_archive_s_own_node(tmp_path, monkeypatch):
    # docs/SPEC_GRAPH_TRACKER.md §6.1 "노드 연결 원칙" -- the archive's own
    # finding node yielded this one, not the bare host/service
    # sync_from_project() would otherwise fall back to (confirmed live: an
    # extracted file was landing on the root node with no clear cause).
    import json
    from app.models import GraphNode
    from app.modules.graph import service as graph_service
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _zip_evidence(db, project, target)
    archive_node = graph_service.create_node(
        db, project.id, "finding", label="파일 다운로드: backup.zip")
    db.commit()

    result = extract_archive_entry(row.id, ArchiveExtractIn(
        entry="notes.txt", graph_node_id=archive_node.id), db=db)

    finding_node = db.query(GraphNode).filter_by(
        project_id=project.id, type="finding", id=archive_node.id).count()
    assert finding_node == 1  # the archive's own node, untouched
    extracted_node = db.query(GraphNode).filter_by(
        project_id=project.id, type="finding").filter(GraphNode.id != archive_node.id).one()
    assert json.loads(extracted_node.source_ref) == {
        "module": "findings", "kind": "finding", "id": result["finding_id"]}
    edge = db.query(GraphEdge).filter_by(
        source=archive_node.id, target=extracted_node.id, relation="yielded").one()
    assert edge is not None


def test_extract_archive_entry_marks_a_password_unlocked_entry_for_the_one_shot_canvas_effect(
        tmp_path, monkeypatch):
    import json
    from app.modules.graph import service as graph_service
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.13")
    db.add(target); db.commit()
    row = _protected_zip_evidence(db, project, target, tmp_path)
    archive_node = graph_service.create_node(
        db, project.id, "finding", label="파일 다운로드: protected.zip")
    db.commit()

    result = extract_archive_entry(row.id, ArchiveExtractIn(
        entry="secret.txt", password="hunter2", graph_node_id=archive_node.id), db=db)

    from app.models import GraphNode
    extracted_node = db.get(GraphNode, db.query(GraphNode).filter_by(
        project_id=project.id, type="finding").filter(GraphNode.id != archive_node.id).one().id)
    assert "unlockedAt" in json.loads(extracted_node.meta)

    # An unencrypted entry (no password given) never got locked in the
    # first place -- it shouldn't play an "unlock" effect either.
    plain_row = _zip_evidence(db, project, target)
    plain_result = extract_archive_entry(plain_row.id, ArchiveExtractIn(
        entry="notes.txt", graph_node_id=archive_node.id), db=db)
    plain_node = db.query(GraphNode).filter_by(
        project_id=project.id, type="finding",
        source_ref=json.dumps({"module": "findings", "kind": "finding",
                               "id": plain_result["finding_id"]}, sort_keys=True)).one()
    assert "unlockedAt" not in json.loads(plain_node.meta)


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


def _protected_zip_evidence(db, project, target, tmp_path):
    import subprocess
    secret_txt = tmp_path / "secret.txt"
    secret_txt.write_text("root:hunter2")
    zip_path = tmp_path / "protected.zip"
    subprocess.run(["zip", "-j", "-P", "hunter2", str(zip_path), str(secret_txt)],
                   check=True, capture_output=True)
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(zip_path.read_bytes())
    uploaded.seek(0)
    return asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="파일 다운로드: protected.zip",
        kind="attachment", description="", service_id=None,
        source_type="interactive_session", source_id=1, sensitivity="normal",
        include_report=False, file=UploadFile(filename="protected.zip", file=uploaded), db=db))


def test_extract_archive_entry_sends_a_password_protected_member_to_hash_cracking_instead_of_500ing(
        tmp_path, monkeypatch):
    # zipfile can list a ZipCrypto-encrypted member's name/size without its
    # password, but .read() on it raises a bare RuntimeError -- this used to
    # surface as an unhandled 500 (confirmed live against a real vulnerable
    # app's protected source zip). It should read as a clear next step
    # instead, since this app already has zip2john (HashCrackingWorkspace)
    # for exactly this.
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _protected_zip_evidence(db, project, target, tmp_path)

    listing = evidence_archive(row.id, db)
    assert listing == {"entries": [{"name": "secret.txt", "size": 12, "encrypted": True}]}

    with pytest.raises(HTTPException) as exc:
        extract_archive_entry(row.id, ArchiveExtractIn(entry="secret.txt"), db=db)
    assert exc.value.status_code == 422
    assert "zip2john" in exc.value.detail


def test_extract_archive_entry_unlocks_a_member_once_the_cracked_password_is_given(
        tmp_path, monkeypatch):
    # The whole point of zip2john/Hash Cracking recovering the password is to
    # come back and actually read the file -- confirmed live there was
    # previously nowhere to put a cracked password back in at all.
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _protected_zip_evidence(db, project, target, tmp_path)

    result = extract_archive_entry(
        row.id, ArchiveExtractIn(entry="secret.txt", password="hunter2"), db=db)

    evidence = db.get(Evidence, result["evidence_id"])
    from pathlib import Path as _Path
    assert _Path(evidence.file_path).read_bytes() == b"root:hunter2"


def test_extract_archive_entry_reports_a_wrong_password_distinctly_from_no_password(
        tmp_path, monkeypatch):
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _protected_zip_evidence(db, project, target, tmp_path)

    with pytest.raises(HTTPException) as exc:
        extract_archive_entry(
            row.id, ArchiveExtractIn(entry="secret.txt", password="wrong"), db=db)
    assert exc.value.status_code == 422
    assert "zip2john" not in exc.value.detail
    assert "올바르지 않습니다" in exc.value.detail


def test_evidence_zip2john_hands_the_archive_straight_to_hash_cracking_without_a_re_upload(
        tmp_path, monkeypatch):
    # No "download it, then re-upload the same file to Hash Cracking" round
    # trip -- the archive is already on disk from the promote/extract flow,
    # so this reads it straight off there.
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    row = _protected_zip_evidence(db, project, target, tmp_path)

    result = evidence_zip2john(row.id, db)

    assert result["hash_mode_id"] == "pkzip"
    assert result["hashes"].startswith("$pkzip$")


def test_evidence_zip2john_selects_the_multi_file_mode_for_a_multi_member_protected_zip(
        tmp_path, monkeypatch):
    # Reproduces the live failure: backup.zip held two encrypted members
    # (index.php, style.css). zip2john folds both into one $pkzip$2*...
    # line, and hashcat mode 17200 (single-file only) rejected that outright
    # with "Hash-value exception" -- confirmed by actually running hashcat
    # against it. hashcat --identify agrees 17220 is the real mode.
    import subprocess
    import app.modules.evidence.router as router
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project = Project(name="Evidence Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="Box", ip="10.10.10.12")
    db.add(target); db.commit()
    (tmp_path / "index.php").write_text("<?php echo 'hi'; ?>")
    (tmp_path / "style.css").write_text("body{}")
    zip_path = tmp_path / "multi.zip"
    subprocess.run(["zip", "-j", "-P", "hunter2", str(zip_path),
                    str(tmp_path / "index.php"), str(tmp_path / "style.css")],
                   check=True, capture_output=True)
    uploaded = tempfile.SpooledTemporaryFile()
    uploaded.write(zip_path.read_bytes())
    uploaded.seek(0)
    row = asyncio.run(upload_evidence(
        project_id=project.id, target_id=target.id, title="파일 다운로드: backup.zip",
        kind="attachment", description="", service_id=None,
        source_type="interactive_session", source_id=1, sensitivity="normal",
        include_report=False, file=UploadFile(filename="backup.zip", file=uploaded), db=db))

    result = evidence_zip2john(row.id, db)

    assert result["hash_mode_id"] == "pkzip_multi_compressed"
    assert result["hashes"].startswith("$pkzip$2*")


def test_evidence_zip2john_rejects_a_non_zip_file(tmp_path, monkeypatch):
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
        evidence_zip2john(row.id, db)
    assert exc.value.status_code == 415
