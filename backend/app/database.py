from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import DB_PATH

class Base(DeclarativeBase):
    pass

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _record):
    # WAL lets readers (e.g. GET /runbooks/instances/{id}) proceed while an
    # execution is mid-stream committing output chunks, instead of hitting
    # "database is locked" under the default rollback-journal mode.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def ensure_compatible_schema() -> None:
    """Upgrade pre-Alembic local databases without discarding user data."""
    columns = {column["name"] for column in inspect(engine).get_columns("scan_jobs")}
    additions = {
        "alias": "ALTER TABLE scan_jobs ADD COLUMN alias VARCHAR(120) NOT NULL DEFAULT ''",
        "tags": "ALTER TABLE scan_jobs ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'",
    }
    with engine.begin() as connection:
        for name, statement in additions.items():
            if name not in columns:
                connection.execute(text(statement))
    tables = inspect(engine)
    service_columns = {column["name"] for column in tables.get_columns("services")}
    execution_columns = {column["name"] for column in tables.get_columns("executions")}
    additions = [
        ("services", "notes", "TEXT NOT NULL DEFAULT ''", service_columns),
        ("services", "tags", "TEXT NOT NULL DEFAULT '[]'", service_columns),
        ("executions", "status", "VARCHAR(20) NOT NULL DEFAULT 'queued'", execution_columns),
        ("executions", "error", "TEXT NOT NULL DEFAULT ''", execution_columns),
        ("executions", "output_path", "TEXT NOT NULL DEFAULT ''", execution_columns),
    ]
    with engine.begin() as connection:
        for table, name, definition, existing in additions:
            if name not in existing:
                connection.execute(text(
                    f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
