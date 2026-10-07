"""add refresh token rotation

Revision ID: e6c4e6d2a121
Revises: 2694b1df888f
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e6c4e6d2a121"
down_revision: Union[str, Sequence[str], None] = "2694b1df888f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing refresh tokens pre-date rotation/token families.
    # They cannot safely participate in the new rotation model,
    # so invalidate those development sessions before changing schema.
    op.execute("DELETE FROM refresh_tokens")

    op.add_column(
        "refresh_tokens",
        sa.Column(
            "family_id",
            sa.UUID(),
            nullable=False,
        ),
    )

    op.add_column(
        "refresh_tokens",
        sa.Column(
            "revoked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    op.add_column(
        "refresh_tokens",
        sa.Column(
            "used_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.create_index(
        op.f("ix_refresh_tokens_family_id"),
        "refresh_tokens",
        ["family_id"],
        unique=False,
    )

    # The default is only needed while establishing the column.
    # New rows get their value from our application model.
    op.alter_column(
        "refresh_tokens",
        "revoked",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_refresh_tokens_family_id"),
        table_name="refresh_tokens",
    )

    op.drop_column(
        "refresh_tokens",
        "used_at",
    )

    op.drop_column(
        "refresh_tokens",
        "revoked",
    )

    op.drop_column(
        "refresh_tokens",
        "family_id",
    )