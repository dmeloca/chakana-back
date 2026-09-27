"""add_vuln_history

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-11 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'vuln_history',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('vuln_id', sa.UUID(as_uuid=True), sa.ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.UUID(as_uuid=True), nullable=True),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('changes', sa.JSON, nullable=False),
        sa.Column('changed_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_vuln_history_vuln_id', 'vuln_history', ['vuln_id'])


def downgrade() -> None:
    op.drop_index('ix_vuln_history_vuln_id', 'vuln_history')
    op.drop_table('vuln_history')
