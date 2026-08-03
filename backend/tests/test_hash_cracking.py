import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Credential, Evidence, HashCrackJob, Project, Target
from app.modules.hash_cracking import catalog, router
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
        "linux_md5crypt", "bcrypt", "winzip", "sevenzip", "rar5", "wpa",
        "werkzeug_pbkdf2", "ike_psk", "sha256", "md5",
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
    ("WPA*02*deadbeef*aabbccddeeff*112233445566*essid***", "wpa"),
    ("pbkdf2:sha256:600000$abc123$deadbeef", "werkzeug_pbkdf2"),
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
