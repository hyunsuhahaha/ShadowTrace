import asyncio
import io
from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Project
from app.modules.directory.router import create_relation, import_objects
from app.schemas import DirectoryRelationIn


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_directory_import_and_observed_relation():
    db = database()
    project = Project(name="AD Lab", description="")
    db.add(project); db.commit()
    content = (
        '[{"kind":"user","name":"alice","domain":"lab.local"},'
        '{"kind":"group","name":"Operators","domain":"lab.local"}]'
    ).encode()
    rows = asyncio.run(import_objects(
        project.id, UploadFile(filename="objects.json",
                               file=io.BytesIO(content)), db))
    relation = create_relation(DirectoryRelationIn(
        project_id=project.id, source_id=rows[0].id, target_id=rows[1].id,
        relation="observed_member_of"), db)
    assert relation.relation == "observed_member_of"
    assert relation.evidence_id is None
