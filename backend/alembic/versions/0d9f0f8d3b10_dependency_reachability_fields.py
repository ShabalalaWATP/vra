"""dependency reachability fields

Revision ID: 0d9f0f8d3b10
Revises: f8c560350b97
Create Date: 2026-04-10 09:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0d9f0f8d3b10"
down_revision: Union[str, None] = "f8c560350b97"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "dependency_findings",
        sa.Column("evidence_type", sa.String(length=40), nullable=False, server_default="exact_package_match"),
    )
    op.add_column(
        "dependency_findings",
        sa.Column("usage_evidence", sa.JSON(), nullable=True),
    )
    op.add_column(
        "dependency_findings",
        sa.Column("reachability_status", sa.String(length=30), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "dependency_findings",
        sa.Column("reachability_confidence", sa.Float(), nullable=True),
    )
    op.add_column(
        "dependency_findings",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "dependency_findings",
        sa.Column("risk_factors", sa.JSON(), nullable=True),
    )
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        op.alter_column("dependency_findings", "evidence_type", server_default=None)
        op.alter_column("dependency_findings", "reachability_status", server_default=None)


def downgrade() -> None:
    op.drop_column("dependency_findings", "risk_factors")
    op.drop_column("dependency_findings", "risk_score")
    op.drop_column("dependency_findings", "reachability_confidence")
    op.drop_column("dependency_findings", "reachability_status")
    op.drop_column("dependency_findings", "usage_evidence")
    op.drop_column("dependency_findings", "evidence_type")
