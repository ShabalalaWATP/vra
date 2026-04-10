"""scan config scanner versions

Revision ID: 7b9f5b95d6c2
Revises: 0d9f0f8d3b10
Create Date: 2026-04-10 11:20:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7b9f5b95d6c2"
down_revision: Union[str, None] = "0d9f0f8d3b10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_configs", sa.Column("codeql_version", sa.String(length=50), nullable=True))
    op.add_column("scan_configs", sa.Column("secrets_version", sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_configs", "secrets_version")
    op.drop_column("scan_configs", "codeql_version")
