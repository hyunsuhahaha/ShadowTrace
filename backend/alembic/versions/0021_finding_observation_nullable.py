"""Allow report findings without a runbook observation."""
from alembic import op
import sqlalchemy as sa

revision = "0021_finding_observation_nullable"
down_revision = "0020_finding_assets"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("observation_id", existing_type=sa.Integer(),
                           nullable=True)

def downgrade():
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("observation_id", existing_type=sa.Integer(),
                           nullable=False)
