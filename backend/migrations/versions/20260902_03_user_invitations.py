"""Add one-time user invitations."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260902_03"
down_revision: str | None = "20260902_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL")
    op.execute(
        """
        CREATE TABLE user_invitations (
            token_hash text PRIMARY KEY CHECK (char_length(token_hash) = 64),
            user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            accepted_at timestamptz,
            CHECK (expires_at > created_at)
        )
        """
    )
    op.execute("CREATE INDEX user_invitations_expires_at_idx ON user_invitations (expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE user_invitations")
    op.execute("DELETE FROM users WHERE password_hash IS NULL")
    op.execute("ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL")
