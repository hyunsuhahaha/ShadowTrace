"""Apply Alembic migrations while adopting pre-Alembic local databases."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from .database import Base, engine, ensure_compatible_schema
from . import models  # noqa: F401


def migrate() -> None:
    backend = Path(__file__).parents[1]
    config = Config(backend / "alembic.ini")
    config.set_main_option("script_location", str(backend / "alembic"))
    tables = set(inspect(engine).get_table_names())
    if not tables:
        command.upgrade(config, "head")
    elif "alembic_version" not in tables:
        Base.metadata.create_all(engine)
        ensure_compatible_schema()
        command.stamp(config, "head")
    else:
        command.upgrade(config, "head")


if __name__ == "__main__":
    migrate()
