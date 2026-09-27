"""rename_analyst_to_manager_add_roles

Revision ID: a132d374ac60
Revises: a9b8c7d6e5f4
Create Date: 2026-06-10 15:24:08.671836

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a132d374ac60'
down_revision: Union[str, Sequence[str], None] = 'a9b8c7d6e5f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE users SET role = 'manager' WHERE role = 'analyst'")
    op.alter_column('users', 'role', server_default='developer')


def downgrade() -> None:
    op.execute("UPDATE users SET role = 'analyst' WHERE role = 'manager'")
    op.alter_column('users', 'role', server_default='analyst')
