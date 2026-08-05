from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Evidence, Project, Target
from app.modules.privesc_analysis import router
from app.modules.privesc_analysis.gtfobins import match_gtfobins
from app.modules.privesc_analysis.schemas import LinpeasIn, SuidScanIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def make_target(db):
    project = Project(name="PrivEsc Lab", description="")
    db.add(project); db.flush()
    target = Target(project_id=project.id, name="box", ip="10.10.10.60")
    db.add(target); db.commit()
    return project, target


# Real linpeas.sh -a output captured locally, trimmed to the banner boundary
# plus a representative slice of findings (AppArmor/Seccomp/kernel-config
# checks, a kernel CVE match, and a world-writable $PATH entry).
LINPEAS_SAMPLE = (
    "\x1b[1;31;103mRED/YELLOW\x1b[0m: 95% a PE vector\n"
    "\x1b[1;33mYELLOW\x1b[0m: Indicates something interesting\n"
    "\x1b[1;33mLinux PE & Hardening\x1b[0m\n"
    "\x1b[1;31m@hacktricks_live\x1b[0m\n"
    "\x1b[1;90mStarting LinPEAS. Caching Writable Folders...\x1b[0m\n"
    "\x1b[1;34m►►► \x1b[1;32mAppArmor profile? .............. \x1b[0m\x1b[0m\x1b[1;31munconfined\x1b[0m\n"
    "\x1b[1;34m►►► \x1b[1;32mSeccomp enabled? ............... \x1b[0m\x1b[0m\x1b[1;31mdisabled\x1b[0m\n"
    "\x1b[1;34m►►► \x1b[1;32mKernel modules loadable?  \x1b[1;90m(T1547.006)\n"
    "\x1b[0m\x1b[1;31mModules can be loaded\x1b[0m\n"
    "\x1b[1;31;103mCVE: CVE-2025-38236 | Name: AF_UNIX MSG_OOB UAF\x1b[0m\n"
    "\x1b[1;31;103m/home/kali/.local/bin:/usr/bin:\x1b[1;31;103m/home/kali\x1b[0m\n"
    "\x1b[1;32mNOT VULNERABLE: reassuring result, not a finding\x1b[0m\n"
)


def test_parse_linpeas_skips_banner_and_classifies_by_color():
    result = router.parse_linpeas(LINPEAS_SAMPLE)
    assert result["critical"] == [
        "CVE: CVE-2025-38236 | Name: AF_UNIX MSG_OOB UAF",
        "/home/kali/.local/bin:/usr/bin:/home/kali",
    ]
    assert result["high"] == [
        "►►► AppArmor profile? .............. unconfined",
        "►►► Seccomp enabled? ............... disabled",
        "Modules can be loaded",
    ]
    assert result["medium"] == []
    # everything before "Starting LinPEAS" — legend text, banner credits — is
    # excluded even though it uses the exact same ANSI colors as real findings
    assert "@hacktricks_live" not in result["high"]
    assert not any("Linux PE" in item for item in result["medium"])
    assert not any("NOT VULNERABLE" in item for item in result["high"] + result["critical"])


def test_parse_linpeas_falls_back_to_whole_text_without_a_boundary_marker():
    partial = "\x1b[1;33mInteresting cron entry: /opt/backup.sh runs as root\x1b[0m\n"
    result = router.parse_linpeas(partial)
    assert result["medium"] == ["Interesting cron entry: /opt/backup.sh runs as root"]


def test_analyze_linpeas_endpoint_saves_evidence_and_returns_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, target = make_target(db)
    response = router.analyze_linpeas(target.id, LinpeasIn(output=LINPEAS_SAMPLE), db)
    assert len(response["critical"]) == 2
    assert len(response["high"]) == 3
    assert response["evidence_id"]

    evidence = db.get(Evidence, response["evidence_id"])
    assert evidence.kind == "linpeas_output"
    assert evidence.sensitivity == "sensitive"
    assert evidence.target_id == target.id
    assert Path(evidence.file_path).read_text(encoding="utf-8") == LINPEAS_SAMPLE
    assert "critical 2" in evidence.description


FIND_SUID_SAMPLE = (
    "find: '/proc/12345/task/12345/fd': Permission denied\n"
    "/usr/bin/find\n"
    "/usr/bin/passwd\n"
    "/usr/bin/bugtracker\n"
    "/usr/lib/openssh/ssh-keysign\n"
    "\n"
)


def test_match_gtfobins_matches_known_suid_binaries_by_basename():
    matches = match_gtfobins(FIND_SUID_SAMPLE)
    binaries = {item["binary"] for item in matches}
    assert binaries == {"find"}
    assert matches[0]["path"] == "/usr/bin/find"
    assert matches[0]["command"] == "find . -exec /bin/sh -p \\; -quit"
    assert matches[0]["reference"] == "https://gtfobins.github.io/gtfobins/find/#suid"
    # passwd, bugtracker (a custom binary, not GTFOBins) and ssh-keysign
    # aren't known SUID GTFOBins entries, and the stderr "Permission
    # denied" line isn't a path at all
    assert "passwd" not in binaries and "bugtracker" not in binaries


def test_match_gtfobins_deduplicates_repeated_paths():
    matches = match_gtfobins("/usr/bin/find\n/usr/bin/find\n")
    assert len(matches) == 1


def test_analyze_suid_endpoint_saves_evidence_and_returns_matches(tmp_path, monkeypatch):
    monkeypatch.setattr(router, "WORKSPACE_DIR", tmp_path)
    db = database()
    project, target = make_target(db)
    response = router.analyze_suid(target.id, SuidScanIn(output=FIND_SUID_SAMPLE), db)
    assert [item["binary"] for item in response["matches"]] == ["find"]
    assert response["evidence_id"]

    evidence = db.get(Evidence, response["evidence_id"])
    assert evidence.kind == "suid_scan"
    assert evidence.sensitivity == "sensitive"
    assert evidence.target_id == target.id
    assert Path(evidence.file_path).read_text(encoding="utf-8") == FIND_SUID_SAMPLE
