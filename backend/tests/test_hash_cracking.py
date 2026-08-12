import asyncio
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base
from app.models import Credential, Evidence, HashCrackJob, Project, Target
from app.modules.hash_cracking import catalog, manager as manager_module, router
from app.modules.hash_cracking.manager import parse_cracked
from app.modules.hash_cracking.schemas import JobIn, PromoteIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def scope(db):
    project = Project(name="Crack Lab", description="")
    other = Project(name="Other Lab", description="")
    db.add_all([project, other]); db.flush()
    target = Target(project_id=project.id, name="DC01", ip="10.10.10.10")
    foreign_target = Target(project_id=other.id, name="Other", ip="10.10.10.11")
    db.add_all([target, foreign_target]); db.flush()
    db.commit()
    return project, other, target, foreign_target


@pytest.fixture
def wordlist(tmp_path, monkeypatch):
    path = tmp_path / "small.txt"
    path.write_text("password1\nsummer2024\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "CANDIDATE_WORDLISTS", [
        {"id": "test_list", "name": "test list", "path": str(path)},
    ])
    monkeypatch.setattr(catalog, "CANDIDATE_RULES", [])
    return path


def test_catalog_lists_hash_modes_and_flags_missing_wordlists(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog, "CANDIDATE_WORDLISTS", [
        {"id": "missing", "name": "missing.txt", "path": str(tmp_path / "nope.txt")},
    ])
    data = router.get_catalog()
    assert any(item["id"] == "kerberoast" and item["mode"] == "13100"
               for item in data["hash_modes"])
    assert data["wordlists"] == [
        {"id": "missing", "name": "missing.txt", "path": str(tmp_path / "nope.txt"),
         "installed": False},
    ]


def test_catalog_covers_the_common_oscp_hash_families():
    ids = {item["id"] for item in catalog.HASH_MODES}
    assert ids == {
        "ntlm", "netntlmv2", "kerberoast", "asreproast", "linux_sha512crypt",
        "linux_md5crypt", "bcrypt", "winzip", "pkzip", "pkzip_uncompressed",
        "pkzip_multi_compressed", "pkzip_multi_mixed", "pkzip_multi_checksum",
        "sevenzip", "rar5", "wpa",
        "ms_office_2007", "ms_office_2010", "ms_office_2013", "keepass", "sha256_salt_pass",
        "werkzeug_pbkdf2", "pbkdf2_sha256_generic", "ike_psk", "sha256", "md5",
    }
    by_id = {item["id"]: item["mode"] for item in catalog.HASH_MODES}
    assert by_id["md5"] == "0"
    assert by_id["sha256"] == "1400"
    assert by_id["bcrypt"] == "3200"
    assert by_id["rar5"] == "13000"
    assert by_id["wpa"] == "22000"
    assert by_id["sevenzip"] == "11600"


@pytest.mark.parametrize("sample, expected", [
    ("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", "ntlm"),
    ("$krb5tgs$23$*user$REALM$spn*$deadbeef", "kerberoast"),
    ("$krb5asrep$23$svc-alfresco@HTB.LOCAL:89bfa3d1", "asreproast"),
    ("$6$saltsalt$hash", "linux_sha512crypt"),
    ("$2y$05$abcdefghijklmnopqrstuv", "bcrypt"),
    ("$7z$2$19$0$salt", "sevenzip"),
    ("$rar5$16$salt$15$iv$8$checksum", "rar5"),
    ("$keepass$*2*60000*0*abcdef", "keepass"),
    ("$pkzip$1*1*2*0*1a4*54c*8664e6d1*0*42*8*1a4*a15b*fdea72d8*$/pkzip$", "pkzip"),
    ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:mysalt123", "sha256_salt_pass"),
    ("$office$*2007*20*128*16*salt*hash*verifier", "ms_office_2007"),
    ("$office$*2010*100000*128*16*salt*hash*verifier", "ms_office_2010"),
    ("$office$*2013*100000*256*16*salt*hash*verifier", "ms_office_2013"),
    ("WPA*02*deadbeef*aabbccddeeff*112233445566*essid***", "wpa"),
    ("pbkdf2:sha256:600000$abc123$deadbeef", "werkzeug_pbkdf2"),
    ("sha256:50000:c2FsdHNhbHQ=:aGFzaGhhc2g=", "pbkdf2_sha256_generic"),
    ("aabbcc:112233:deadbeef:cafebabe:1122ff:aa11bb:cc22dd:ee33ff:1", "ike_psk"),
    ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "sha256"),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "md5"),
    ("not a recognizable hash", None),
    ("", None),
])
def test_detect_hash_mode_matches_known_formats(sample, expected):
    assert catalog.detect_hash_mode(sample) == expected


def test_werkzeug_pbkdf2_line_is_reencoded_to_hashcat_mode_10900_format():
    import base64
    # Werkzeug's own storage string: pbkdf2:sha256:<iter>$<ascii salt>$<hex digest>
    line = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$" + "0673ad90a0b4afb19d662336f0fce3a9" * 2
    converted = catalog.to_hashcat_line("werkzeug_pbkdf2", line)
    scheme, iterations, salt_b64, hash_b64 = converted.split(":")
    assert scheme == "sha256"
    assert iterations == "600000"
    assert base64.b64decode(salt_b64) == b"AMtzteQIG7yAbZIa"
    assert base64.b64decode(hash_b64).hex() == "0673ad90a0b4afb19d662336f0fce3a9" * 2
    # a mode with no registered transform (or a line that doesn't match the
    # expected shape) passes through unchanged
    assert catalog.to_hashcat_line("ntlm", "aad3b435:31d6cfe0") == "aad3b435:31d6cfe0"
    assert catalog.to_hashcat_line("werkzeug_pbkdf2", "not-the-right-shape") == \
        "not-the-right-shape"


def test_create_job_reencodes_werkzeug_hashes_before_writing_the_hash_file(
        wordlist, tmp_path, monkeypatch):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, _other, target, _foreign = scope(db)
    line = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$" + "0673ad90a0b4afb19d662336f0fce3a9" * 2
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="werkzeug_pbkdf2",
        hashes=line, wordlist_id="test_list"), db)
    assert job.hash_mode == "10900"
    folder = router_module.job_directory(project, target, job.id)
    written = (folder / "hashes.txt").read_text(encoding="utf-8").strip()
    assert written.startswith("sha256:600000:")
    assert written != line


def test_create_job_requires_known_hash_mode_and_wordlist(wordlist):
    db = database()
    project, _other, target, _foreign = scope(db)
    with pytest.raises(HTTPException) as exc:
        router.create_job(JobIn(
            project_id=project.id, target_id=target.id, hash_mode_id="not-a-mode",
            hashes="hash1", wordlist_id="test_list"), db)
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException):
        router.create_job(JobIn(
            project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
            hashes="hash1", wordlist_id="not-a-wordlist"), db)


def test_create_job_rejects_target_from_another_project(wordlist):
    db = database()
    project, _other, _target, foreign_target = scope(db)
    with pytest.raises(HTTPException) as exc:
        router.create_job(JobIn(
            project_id=project.id, target_id=foreign_target.id, hash_mode_id="ntlm",
            hashes="aad3b435:31d6cfe0", wordlist_id="test_list"), db)
    assert exc.value.status_code == 400


def test_create_job_builds_argv_and_writes_hash_file(wordlist, tmp_path, monkeypatch):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, _other, target, _foreign = scope(db)
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="kerberoast",
        hashes="$krb5tgs$23$*user$REALM$spn*$deadbeef\n\n", wordlist_id="test_list"), db)
    assert job.hash_count == 1
    assert job.hash_mode == "13100"
    argv = json.loads(db.get(HashCrackJob, job.id).argv_json)
    assert argv[:6] == ["hashcat", "-m", "13100", "-a", "0", "--potfile-disable"]
    assert "hashes.txt" in argv and str(wordlist) in argv
    folder = router_module.job_directory(project, target, job.id)
    assert (folder / "hashes.txt").read_text(encoding="utf-8").strip() == \
        "$krb5tgs$23$*user$REALM$spn*$deadbeef"


def test_create_job_appends_rule_flag_when_selected(wordlist, tmp_path, monkeypatch):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    rule_path = tmp_path / "best64.rule"
    rule_path.write_text(":\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "CANDIDATE_RULES", [
        {"id": "best64", "name": "best64.rule", "path": str(rule_path)},
    ])
    db = database()
    project, _other, target, _foreign = scope(db)
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        wordlist_id="test_list", rule_id="best64"), db)
    argv = json.loads(db.get(HashCrackJob, job.id).argv_json)
    assert argv[-2:] == ["-r", str(rule_path)]


def test_create_job_combination_mode_needs_two_wordlists(wordlist, tmp_path, monkeypatch):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    second = tmp_path / "second.txt"
    second.write_text("suffix1\nsuffix2\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "CANDIDATE_WORDLISTS", [
        {"id": "test_list", "name": "test list", "path": str(wordlist)},
        {"id": "second_list", "name": "second list", "path": str(second)},
    ])
    db = database()
    project, _other, target, _foreign = scope(db)
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        attack_mode="1", wordlist_id="test_list", wordlist2_id="second_list"), db)
    argv = json.loads(db.get(HashCrackJob, job.id).argv_json)
    assert argv[:6] == ["hashcat", "-m", "1000", "-a", "1", "--potfile-disable"]
    assert argv[-2:] == [str(wordlist), str(second)]
    with pytest.raises(HTTPException):
        router.create_job(JobIn(
            project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
            hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            attack_mode="1", wordlist_id="test_list"), db)


def test_create_job_brute_force_mode_uses_a_validated_mask(wordlist, tmp_path, monkeypatch):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, _other, target, _foreign = scope(db)
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        attack_mode="3", mask="?u?l?l?l?l?d?d?d"), db)
    argv = json.loads(db.get(HashCrackJob, job.id).argv_json)
    assert argv[:6] == ["hashcat", "-m", "1000", "-a", "3", "--potfile-disable"]
    assert argv[-1] == "?u?l?l?l?l?d?d?d"
    with pytest.raises(HTTPException):
        router.create_job(JobIn(
            project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
            hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            attack_mode="3", mask=""), db)


def test_create_job_rejects_a_mask_disguised_as_a_hashcat_flag(wordlist):
    db = database()
    project, _other, target, _foreign = scope(db)
    with pytest.raises(HTTPException):
        router.create_job(JobIn(
            project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
            hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            attack_mode="3", mask="--session=evil"), db)


@pytest.mark.parametrize("attack_mode", ["6", "7"])
def test_create_job_hybrid_modes_order_wordlist_and_mask_correctly(
        wordlist, tmp_path, monkeypatch, attack_mode):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, _other, target, _foreign = scope(db)
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        attack_mode=attack_mode, wordlist_id="test_list", mask="?d?d?d?d"), db)
    argv = json.loads(db.get(HashCrackJob, job.id).argv_json)
    assert argv[:6] == ["hashcat", "-m", "1000", "-a", attack_mode, "--potfile-disable"]
    if attack_mode == "6":
        assert argv[-2:] == [str(wordlist), "?d?d?d?d"]
    else:
        assert argv[-2:] == ["?d?d?d?d", str(wordlist)]


def test_parse_cracked_splits_on_last_colon(tmp_path):
    path = tmp_path / "cracked.txt"
    path.write_text(
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:P@ssw0rd:extra\n"
        "$krb5tgs$23$*user$REALM$spn*$deadbeef:Summer2024\n",
        encoding="utf-8")
    results = parse_cracked(path)
    assert results[0]["plain"] == "extra"
    assert results[1] == {"hash": "$krb5tgs$23$*user$REALM$spn*$deadbeef", "plain": "Summer2024"}


def test_parse_cracked_missing_file_returns_empty(tmp_path):
    assert parse_cracked(tmp_path / "missing.txt") == []


def test_promote_creates_credential_linked_to_job(wordlist, tmp_path, monkeypatch):
    from app.modules.hash_cracking import router as router_module
    monkeypatch.setattr(router_module, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, _other, target, _foreign = scope(db)
    job = router.create_job(JobIn(
        project_id=project.id, target_id=target.id, hash_mode_id="ntlm",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        wordlist_id="test_list"), db)
    result = router.promote(job.id, PromoteIn(username="administrator", secret="P@ssw0rd"), db)
    credential = db.get(Credential, result["id"])
    assert credential.username == "administrator"
    assert credential.secret == "P@ssw0rd"
    assert credential.source_kind == "hash_crack"
    assert credential.target_id == target.id
    assert f"Hash crack #{job.id}" in credential.source_detail


def upload(content: bytes, filename: str = "backup.zip") -> UploadFile:
    spooled = tempfile.SpooledTemporaryFile()
    spooled.write(content)
    spooled.seek(0)
    return UploadFile(filename=filename, file=spooled)


def test_zip2john_reports_not_installed_without_the_binary(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router.zip2john(upload(b"PK\x03\x04fake zip")))
    assert exc.value.status_code == 409


def test_zip2john_extracts_a_pkzip_hash_and_selects_the_pkzip_mode(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/zip2john")
    stdout = ("upload.zip:$pkzip$1*1*2*0*1a4*54c*8664e6d1*0*42*8*1a4*a15b*"
              "fdea72d8524a084d7276df6db4a3f8a*$/pkzip$:::upload.zip:test.txt:upload.zip\n")

    def fake_run(argv, **kwargs):
        assert argv[0] == "/usr/bin/zip2john"
        return SimpleNamespace(stdout=stdout, stderr="", returncode=0)
    monkeypatch.setattr(router.subprocess, "run", fake_run)

    result = asyncio.run(router.zip2john(upload(b"fake zip bytes")))
    assert result["hash_mode_id"] == "pkzip"
    assert result["hashes"] == (
        "$pkzip$1*1*2*0*1a4*54c*8664e6d1*0*42*8*1a4*a15b*fdea72d8524a084d7276df6db4a3f8a*$/pkzip$")


def test_zip2john_extracts_a_winzip_hash_and_selects_the_winzip_mode(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/zip2john")
    stdout = "upload.zip:$zip2$*0*3*0*salt*verify*10*data*hmac*$/zip2$:::upload.zip:secret.docx:upload.zip\n"

    def fake_run(argv, **kwargs):
        return SimpleNamespace(stdout=stdout, stderr="", returncode=0)
    monkeypatch.setattr(router.subprocess, "run", fake_run)

    result = asyncio.run(router.zip2john(upload(b"fake zip bytes")))
    assert result["hash_mode_id"] == "winzip"
    assert result["hashes"].startswith("$zip2$")


def test_zip2john_raises_422_when_no_hash_is_found(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/zip2john")

    def fake_run(argv, **kwargs):
        return SimpleNamespace(stdout="", stderr="upload.zip is not encrypted!\n", returncode=0)
    monkeypatch.setattr(router.subprocess, "run", fake_run)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(router.zip2john(upload(b"fake zip bytes")))
    assert exc.value.status_code == 422
    assert "not encrypted" in str(exc.value.detail)


def test_zip2john_rejects_uploads_over_the_size_limit(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/zip2john")
    monkeypatch.setattr(router, "ZIP_MAX_BYTES", 10)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router.zip2john(upload(b"x" * 20)))
    assert exc.value.status_code == 413


def test_zip2john_times_out(monkeypatch):
    import subprocess as subprocess_module
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/zip2john")

    def timeout(*args, **kwargs):
        raise subprocess_module.TimeoutExpired(cmd="zip2john", timeout=60)
    monkeypatch.setattr(router.subprocess, "run", timeout)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(router.zip2john(upload(b"fake zip bytes")))
    assert exc.value.status_code == 504


def test_hashcat_runs_with_rusticl_enabled_for_the_cpu_opencl_fallback(tmp_path, monkeypatch):
    # Mesa's rusticl OpenCL platform (the CPU fallback used on a GPU-less
    # box, e.g. most VMs) enumerates zero devices unless this env var is
    # set, which hashcat treats as "no compatible platform found" and
    # exits immediately without cracking anything.
    engine = create_engine(f"sqlite:///{tmp_path / 'jobs.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    with factory() as db:
        project = Project(name="Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.10")
        db.add(target); db.flush()
        job = HashCrackJob(
            project_id=project.id, target_id=target.id, hash_mode_id="netntlmv2",
            hash_mode="5600", hash_type_name="NetNTLMv2", attack_mode="0",
            hash_count=1, status="running")
        db.add(job); db.commit()
        job_id = job.id

    folder = tmp_path / "job"
    script = tmp_path / "print_env.py"
    script.write_text("import os\nprint(os.environ.get('RUSTICL_ENABLE', ''))\n",
                      encoding="utf-8")

    async def run():
        manager_module.manager.cancel_events[job_id] = asyncio.Event()
        await manager_module.manager._run(job_id, [sys.executable, str(script)], folder)
    asyncio.run(run())

    assert (folder / "stdout.txt").read_text(encoding="utf-8").strip() == "llvmpipe"


def test_manager_captures_evidence_when_the_process_fails_to_spawn(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'spawnfail.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(manager_module, "SessionLocal", factory)
    with factory() as db:
        project = Project(name="Lab", description="")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.11")
        db.add(target); db.flush()
        job = HashCrackJob(
            project_id=project.id, target_id=target.id, hash_mode_id="netntlmv2",
            hash_mode="5600", hash_type_name="NetNTLMv2", attack_mode="0",
            hash_count=1, status="running")
        db.add(job); db.commit()
        job_id = job.id

    folder = tmp_path / "spawnfail-job"

    async def run():
        manager_module.manager.cancel_events[job_id] = asyncio.Event()
        await manager_module.manager._run(
            job_id, ["/nonexistent/binary/that/does/not/exist"], folder)
    asyncio.run(run())

    with factory() as db:
        finished = db.get(HashCrackJob, job_id)
        assert finished.status == "failed"
        assert finished.evidence_id is not None
        evidence = db.get(Evidence, finished.evidence_id)
        assert evidence.source_type == "hash_crack_job"
        assert "No such file" in Path(evidence.file_path).read_text()
