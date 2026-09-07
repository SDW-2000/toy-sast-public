"""Add metadata-only scan file manifests."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260831_01"
down_revision: str | None = "20260830_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_runs
        ADD COLUMN manifest_version smallint,
        ADD COLUMN manifest_node_count integer
        """
    )
    op.execute(
        """
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_manifest_snapshot_check CHECK (
            (manifest_version IS NULL AND manifest_node_count IS NULL)
            OR (manifest_version = 1 AND manifest_node_count BETWEEN 1 AND 20000)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE scan_files (
            scan_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            path text NOT NULL,
            parent_path text,
            depth smallint NOT NULL CHECK (depth BETWEEN 1 AND 64),
            node_type text NOT NULL CHECK (node_type IN ('DIRECTORY', 'FILE')),
            size bigint NOT NULL CHECK (size >= 0),
            language text CHECK (language IN ('Java', 'JavaScript', 'Python')),
            state text NOT NULL CHECK (state IN (
                'DIRECTORY', 'TARGET', 'EXCLUDED_DIRECTORY', 'UNSUPPORTED_EXTENSION'
            )),
            finding_count integer NOT NULL CHECK (finding_count >= 0),
            PRIMARY KEY (scan_id, path),
            CONSTRAINT scan_files_path_bytes_check CHECK (
                octet_length(path) BETWEEN 1 AND 4096
                AND (parent_path IS NULL OR octet_length(parent_path) BETWEEN 1 AND 4096)
            ),
            CONSTRAINT scan_files_shape_check CHECK (
                (node_type = 'DIRECTORY' AND state = 'DIRECTORY'
                    AND size = 0 AND language IS NULL)
                OR (node_type = 'FILE' AND state <> 'DIRECTORY'
                    AND ((state = 'TARGET') = (language IS NOT NULL)))
            ),
            CONSTRAINT scan_files_parent_fkey
                FOREIGN KEY (scan_id, parent_path)
                REFERENCES scan_files(scan_id, path)
                DEFERRABLE INITIALLY DEFERRED
        )
        """
    )
    op.execute(
        """
        CREATE INDEX scan_files_children_idx ON scan_files (
            scan_id,
            parent_path,
            (CASE WHEN node_type = 'DIRECTORY' THEN 0 ELSE 1 END),
            path COLLATE "C"
        )
        """
    )
    op.execute(
        """
        CREATE INDEX scan_files_target_idx
        ON scan_files (scan_id, path COLLATE "C") WHERE state = 'TARGET'
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE scan_files")
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_manifest_snapshot_check")
    op.execute("ALTER TABLE scan_runs DROP COLUMN manifest_node_count")
    op.execute("ALTER TABLE scan_runs DROP COLUMN manifest_version")
