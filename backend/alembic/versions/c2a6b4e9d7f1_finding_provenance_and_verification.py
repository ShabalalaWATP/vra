"""finding provenance and verification metadata

Revision ID: c2a6b4e9d7f1
Revises: 9c6f0a4c1b2d
Create Date: 2026-04-13 11:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c2a6b4e9d7f1"
down_revision: Union[str, None] = "9c6f0a4c1b2d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("provenance", sa.String(length=20), nullable=True))
    op.add_column("findings", sa.Column("source_scanners", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("source_rules", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("verification_level", sa.String(length=32), nullable=True))
    op.add_column("findings", sa.Column("verification_notes", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("canonical_key", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("merge_metadata", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "merge_metadata")
    op.drop_column("findings", "canonical_key")
    op.drop_column("findings", "verification_notes")
    op.drop_column("findings", "verification_level")
    op.drop_column("findings", "source_rules")
    op.drop_column("findings", "source_scanners")
    op.drop_column("findings", "provenance")
