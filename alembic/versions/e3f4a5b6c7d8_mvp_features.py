"""mvp_features

Revision ID: e3f4a5b6c7d8
Revises: 244de3754e73
Create Date: 2026-06-10 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'e3f4a5b6c7d8'
down_revision: Union[str, Sequence[str], None] = '244de3754e73'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('vulnerabilities', sa.Column('assigned_to', sa.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key('fk_vulns_assigned_to', 'vulnerabilities', 'users', ['assigned_to'], ['id'])
    op.add_column('vulnerabilities', sa.Column('due_date', sa.DateTime(timezone=True), nullable=True))
    op.add_column('vulnerabilities', sa.Column('cve_id', sa.String(20), nullable=True))
    op.add_column('vulnerabilities', sa.Column('cvss_score', sa.Float, nullable=True))

    op.create_table(
        'comments',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('vuln_id', sa.UUID(as_uuid=True), sa.ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('body', sa.Text, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_comments_vuln_id', 'comments', ['vuln_id'])


def downgrade() -> None:
    op.drop_index('ix_comments_vuln_id', table_name='comments')
    op.drop_table('comments')
    op.drop_constraint('fk_vulns_assigned_to', 'vulnerabilities', type_='foreignkey')
    op.drop_column('vulnerabilities', 'cvss_score')
    op.drop_column('vulnerabilities', 'cve_id')
    op.drop_column('vulnerabilities', 'due_date')
    op.drop_column('vulnerabilities', 'assigned_to')
