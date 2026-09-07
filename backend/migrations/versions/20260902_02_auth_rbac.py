"""Add local users, project membership, and opaque sessions."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260902_02"
down_revision: str | None = "20260902_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE users (
            id uuid PRIMARY KEY,
            email text NOT NULL UNIQUE CHECK (email = lower(email)),
            password_hash text NOT NULL,
            role text NOT NULL CHECK (role IN ('ADMIN', 'USER')),
            is_active boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE project_members (
            project_id text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (project_id, user_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE sessions (
            token_hash text PRIMARY KEY CHECK (char_length(token_hash) = 64),
            user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            CHECK (expires_at > created_at)
        )
        """
    )
    op.execute("CREATE INDEX sessions_expires_at_idx ON sessions (expires_at)")
    op.execute("CREATE INDEX project_members_user_idx ON project_members (user_id, project_id)")


def downgrade() -> None:
    op.execute("DROP TABLE sessions")
    op.execute("DROP TABLE project_members")
    op.execute("DROP TABLE users")
