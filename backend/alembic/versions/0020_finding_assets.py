"""Add multiple affected assets to findings."""
from alembic import op
import sqlalchemy as sa

revision = "0020_finding_assets"
down_revision = "0019_finding_scope_nullable"
branch_labels = None
depends_on = None

def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "finding_assets" not in tables:
      op.create_table("finding_assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("services.id", ondelete="CASCADE"), nullable=True))
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("finding_assets")}
    if "uq_finding_asset" not in indexes:
        op.create_index("uq_finding_asset", "finding_assets",
                        ["finding_id", "target_id", "service_id"], unique=True)
    op.execute("""INSERT INTO finding_assets (finding_id, target_id, service_id)
                  SELECT f.id, f.target_id, f.service_id FROM findings f
                  WHERE f.target_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM finding_assets a
                    WHERE a.finding_id=f.id AND a.target_id=f.target_id
                    AND (a.service_id=f.service_id OR
                         (a.service_id IS NULL AND f.service_id IS NULL)))""")

def downgrade():
    op.drop_index("uq_finding_asset", table_name="finding_assets")
    op.drop_table("finding_assets")
