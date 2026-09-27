"""add_cvss_vector_cwe

Revision ID: b2c3d4e5f6a7
Revises: a9b8c7d6e5f4
Create Date: 2026-06-11 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = '1fd45801f7a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('vulnerabilities', sa.Column('cvss_vector', sa.String(100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('cwe_id', sa.String(20), nullable=True))


def downgrade() -> None:
    op.drop_column('vulnerabilities', 'cwe_id')
    op.drop_column('vulnerabilities', 'cvss_vector')
