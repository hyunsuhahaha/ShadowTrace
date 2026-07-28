import sqlite3
import zipfile
from app.modules.operations.router import create_backup


def test_backup_contains_consistent_database_and_artifacts(tmp_path, monkeypatch):
    import app.modules.operations.router as router
    database = tmp_path / "workspace.db"
    connection = sqlite3.connect(database)
    connection.execute("create table sample (value text)")
    connection.execute("insert into sample values ('preserved')")
    connection.commit(); connection.close()
    workspace = tmp_path / "artifacts-source"
    workspace.mkdir()
    (workspace / "proof.txt").write_text("proof", encoding="utf-8")
    state = tmp_path / "state"
    monkeypatch.setattr(router, "DB_PATH", database)
    monkeypatch.setattr(router, "WORKSPACE_DIR", workspace)
    monkeypatch.setattr(router, "STATE_DIR", state)
    result = create_backup()
    archive = state / "backups" / result["name"]
    with zipfile.ZipFile(archive) as backup:
        assert "workspace.db" in backup.namelist()
        assert "artifacts/proof.txt" in backup.namelist()
