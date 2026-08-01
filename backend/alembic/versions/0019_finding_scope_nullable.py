"""Allow project-wide findings without a target."""
from alembic import op
import sqlalchemy as sa

revision = "0019_finding_scope_nullable"
down_revision = "0018_findings"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("target_id", existing_type=sa.Integer(), nullable=True)

def downgrade():
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("target_id", existing_type=sa.Integer(), nullable=False)
