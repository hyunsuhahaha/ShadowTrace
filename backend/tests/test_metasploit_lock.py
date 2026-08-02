import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import set_metasploit_lock
from app.models import Base, Project, Target
from app.schemas import MetasploitLockIn


def database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'msf.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def seed(db):
    project = Project(name="Exam", description="")
    db.add(project); db.flush()
    a = Target(project_id=project.id, name="A", ip="198.51.100.10")
    b = Target(project_id=project.id, name="B", ip="198.51.100.11")
    db.add_all([a, b]); db.commit()
    return project, a, b


def test_locking_a_target_records_it(tmp_path):
    db = database(tmp_path)
    project, a, _b = seed(db)

    updated = set_metasploit_lock(project.id, MetasploitLockIn(target_id=a.id), db)

    assert updated.metasploit_target_id == a.id
    assert updated.metasploit_locked_at is not None
    db.close()


def test_locking_a_second_target_is_allowed_at_the_data_layer(tmp_path):
    # The lock is a warning surface for the UI, not an enforcement mechanism —
    # the backend must not hard-block a second target (the user may need to
    # correct a mistaken lock), so re-locking always succeeds here.
    db = database(tmp_path)
    project, a, b = seed(db)
    set_metasploit_lock(project.id, MetasploitLockIn(target_id=a.id), db)

    updated = set_metasploit_lock(project.id, MetasploitLockIn(target_id=b.id), db)

    assert updated.metasploit_target_id == b.id
    db.close()


def test_clearing_the_lock_resets_timestamp(tmp_path):
    db = database(tmp_path)
    project, a, _b = seed(db)
    set_metasploit_lock(project.id, MetasploitLockIn(target_id=a.id), db)

    cleared = set_metasploit_lock(project.id, MetasploitLockIn(target_id=None), db)

    assert cleared.metasploit_target_id is None
    assert cleared.metasploit_locked_at is None
    db.close()


def test_target_from_a_different_project_is_rejected(tmp_path):
    db = database(tmp_path)
    project, _a, _b = seed(db)
    other_project = Project(name="Other", description="")
    db.add(other_project); db.flush()
    foreign_target = Target(
        project_id=other_project.id, name="C", ip="198.51.100.12")
    db.add(foreign_target); db.commit()

    with pytest.raises(HTTPException) as excinfo:
        set_metasploit_lock(
            project.id, MetasploitLockIn(target_id=foreign_target.id), db)
    assert excinfo.value.status_code == 400
    db.close()
