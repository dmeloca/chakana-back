"""vuln_fk_on_delete

Revision ID: 1fd45801f7a7
Revises: a132d374ac60
Create Date: 2026-06-10 15:50:28.502756

"""
from typing import Sequence, Union

from alembic import op

revision: str = '1fd45801f7a7'
down_revision: Union[str, Sequence[str], None] = 'a132d374ac60'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint('fk_vulns_assigned_to', 'vulnerabilities', type_='foreignkey')
    op.create_foreign_key(
        'fk_vulns_assigned_to',
        'vulnerabilities', 'users',
        ['assigned_to'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint('fk_vulns_assigned_to', 'vulnerabilities', type_='foreignkey')
    op.create_foreign_key(
        'fk_vulns_assigned_to',
        'vulnerabilities', 'users',
        ['assigned_to'], ['id'],
    )
