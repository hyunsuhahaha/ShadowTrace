"""Track stable built-in runbook identities."""
from alembic import op
import sqlalchemy as sa

revision = "0017_builtin_runbooks"
down_revision = "0016_runbook_operations"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("runbook_templates",
                  sa.Column("builtin_key", sa.String(120), nullable=True))
    op.create_index("uq_runbook_templates_builtin_key", "runbook_templates",
                    ["builtin_key"], unique=True)


def downgrade():
    op.drop_index("uq_runbook_templates_builtin_key",
                  table_name="runbook_templates")
    op.drop_column("runbook_templates", "builtin_key")
