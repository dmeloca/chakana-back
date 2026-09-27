"""add_user_roles

Revision ID: a9b8c7d6e5f4
Revises: e3f4a5b6c7d8
Create Date: 2026-06-10 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a9b8c7d6e5f4'
down_revision: Union[str, Sequence[str], None] = 'e3f4a5b6c7d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('role', sa.String(10), nullable=False, server_default='analyst'),
    )
    # Promote the seeded admin account
    op.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")


def downgrade() -> None:
    op.drop_column('users', 'role')
