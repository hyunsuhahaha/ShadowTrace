from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Credential, Project, Service, Target
from app.modules.notes.router import create_note, delete_note, list_notes, update_note
from app.schemas import NoteIn, NoteUpdate


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def scope(db):
    project = Project(name="Note Lab", description="")
    other = Project(name="Other Lab", description="")
    db.add_all([project, other]); db.flush()
    target = Target(project_id=project.id, name="DC01", ip="10.10.10.10")
    foreign_target = Target(project_id=other.id, name="Foreign", ip="10.10.10.20")
    db.add_all([target, foreign_target]); db.flush()
    service = Service(target_id=target.id, port=445, name="microsoft-ds")
    db.add(service); db.commit()
    return project, other, target, foreign_target, service


def test_create_note_scoped_to_project_only():
    db = database()
    project, *_ = scope(db)
    note = create_note(NoteIn(project_id=project.id, body="watch for MS17-010"), db)
    assert note.id is not None
    assert note.body == "watch for MS17-010"
    assert note.target_id is None
    assert note.created_at is not None


def test_create_note_scoped_to_a_target_and_service():
    db = database()
    project, _other, target, _foreign, service = scope(db)
    note = create_note(NoteIn(
        project_id=project.id, target_id=target.id, service_id=service.id,
        body="SMB signing disabled", author="operator"), db)
    assert note.target_id == target.id
    assert note.service_id == service.id
    assert note.author == "operator"


def test_create_note_rejects_a_target_from_another_project():
    db = database()
    project, _other, _target, foreign_target, _service = scope(db)
    with pytest.raises(HTTPException) as exc:
        create_note(NoteIn(
            project_id=project.id, target_id=foreign_target.id, body="x"), db)
    assert exc.value.status_code == 400


def test_create_note_rejects_a_service_without_its_owning_target():
    db = database()
    project, _other, target, _foreign, service = scope(db)
    with pytest.raises(HTTPException) as exc:
        create_note(NoteIn(
            project_id=project.id, service_id=service.id, body="x"), db)
    assert exc.value.status_code == 400


def test_create_note_can_attach_to_a_credential():
    db = database()
    project, _other, target, _foreign, service = scope(db)
    credential = Credential(project_id=project.id, target_id=target.id, username="alice")
    db.add(credential); db.commit()
    note = create_note(NoteIn(
        project_id=project.id, credential_id=credential.id,
        body="reused on the domain controller"), db)
    assert note.credential_id == credential.id


def test_create_note_rejects_a_credential_from_another_project():
    db = database()
    project, other, _target, _foreign, _service = scope(db)
    credential = Credential(project_id=other.id, username="bob")
    db.add(credential); db.commit()
    with pytest.raises(HTTPException) as exc:
        create_note(NoteIn(
            project_id=project.id, credential_id=credential.id, body="x"), db)
    assert exc.value.status_code == 400


def test_list_notes_filters_by_project_and_target():
    db = database()
    project, other, target, foreign_target, _service = scope(db)
    create_note(NoteIn(project_id=project.id, body="project-wide"), db)
    create_note(NoteIn(project_id=project.id, target_id=target.id, body="target-scoped"), db)
    create_note(NoteIn(project_id=other.id, target_id=foreign_target.id, body="elsewhere"), db)

    project_notes = list_notes(project_id=project.id, db=db)
    assert {row.body for row in project_notes} == {"project-wide", "target-scoped"}

    target_notes = list_notes(project_id=project.id, target_id=target.id, db=db)
    assert [row.body for row in target_notes] == ["target-scoped"]


def test_update_note_changes_body_and_updated_at():
    db = database()
    project, *_ = scope(db)
    note = create_note(NoteIn(project_id=project.id, body="first draft"), db)
    original_updated_at = note.updated_at
    updated = update_note(note.id, NoteUpdate(body="revised"), db)
    assert updated.body == "revised"
    assert updated.updated_at >= original_updated_at


def test_delete_note_removes_it():
    db = database()
    project, *_ = scope(db)
    note = create_note(NoteIn(project_id=project.id, body="temporary"), db)
    delete_note(note.id, db)
    assert list_notes(project_id=project.id, db=db) == []


def test_delete_note_404s_for_an_unknown_id():
    db = database()
    with pytest.raises(HTTPException) as exc:
        delete_note(999, db)
    assert exc.value.status_code == 404
