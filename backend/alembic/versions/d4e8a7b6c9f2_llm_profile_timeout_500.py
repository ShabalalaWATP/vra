"""llm profile timeout default 500

Revision ID: d4e8a7b6c9f2
Revises: c2a6b4e9d7f1
Create Date: 2026-04-29 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d4e8a7b6c9f2"
down_revision: Union[str, None] = "c2a6b4e9d7f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE llm_profiles SET timeout_seconds = 500 WHERE timeout_seconds = 120")


def downgrade() -> None:
    op.execute("UPDATE llm_profiles SET timeout_seconds = 120 WHERE timeout_seconds = 500")
