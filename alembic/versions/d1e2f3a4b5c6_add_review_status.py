"""add_review_status

Revision ID: d1e2f3a4b5c6
Revises: c3d4e5f6a7b8
Create Date: 2026-06-13 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_enum = sa.Enum('pending', 'approved', 'rejected', name='reviewstatus')


def upgrade() -> None:
    _enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        'vulnerabilities',
        sa.Column('review_status', _enum, nullable=False, server_default='pending'),
    )
    # Backfill: existing vulns pre-date the workflow, treat them as already approved
    op.execute("UPDATE vulnerabilities SET review_status = 'approved'")


def downgrade() -> None:
    op.drop_column('vulnerabilities', 'review_status')
    op.execute('DROP TYPE reviewstatus')
