"""rename_criticality_to_severity

Revision ID: 244de3754e73
Revises: 128ecf0f0ba4
Create Date: 2026-06-09 23:29:23.826152

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '244de3754e73'
down_revision: Union[str, Sequence[str], None] = '128ecf0f0ba4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("vulnerabilities", "criticality", new_column_name="severity")
    op.execute("ALTER TYPE criticality RENAME TO severity")


def downgrade() -> None:
    op.alter_column("vulnerabilities", "severity", new_column_name="criticality")
    op.execute("ALTER TYPE severity RENAME TO criticality")
