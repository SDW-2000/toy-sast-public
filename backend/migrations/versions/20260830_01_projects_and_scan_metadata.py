"""Adopt the scan schema and add projects plus immutable scan metadata."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260830_01"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id text PRIMARY KEY,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
            description text NOT NULL DEFAULT '',
            assigned_to_viewer boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id uuid PRIMARY KEY,
            project_id text NOT NULL,
            archive_name text NOT NULL,
            archive_data bytea,
            status text NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
            phase text NOT NULL CHECK (phase IN (
                'PENDING', 'ZIP_VALIDATION', 'LANGUAGE_DETECTION', 'ANALYZING',
                'NORMALIZING', 'COMPLETED', 'FAILED'
            )),
            progress_percent smallint CHECK (progress_percent BETWEEN 0 AND 100),
            completed_units integer NOT NULL DEFAULT 0 CHECK (completed_units >= 0),
            total_units integer CHECK (total_units > 0),
            CONSTRAINT scan_runs_progress_units_check
                CHECK (total_units IS NULL OR completed_units <= total_units),
            CONSTRAINT scan_runs_completion_progress_check CHECK (
                (status = 'COMPLETED' AND progress_percent = 100
                    AND total_units IS NOT NULL AND completed_units = total_units)
                OR (status <> 'COMPLETED' AND (progress_percent IS NULL OR progress_percent < 100))
            ),
            message text NOT NULL,
            detected_languages jsonb NOT NULL DEFAULT '[]'::jsonb,
            language_file_counts jsonb NOT NULL DEFAULT '{}'::jsonb,
            archive_file_count integer CHECK (archive_file_count >= 0),
            analysis_file_count integer CHECK (analysis_file_count >= 0),
            engine_name text,
            engine_version text,
            rulepack_name text,
            rulepack_version text,
            ruleset_digest text,
            registered_rule_count integer CHECK (registered_rule_count >= 0),
            supported_rule_count integer CHECK (supported_rule_count >= 0),
            error_code text,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    for statement in (
        """
        ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS language_file_counts
        jsonb NOT NULL DEFAULT '{}'::jsonb
        """,
        """
        ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS archive_file_count
        integer CHECK (archive_file_count >= 0)
        """,
        """
        ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS analysis_file_count
        integer CHECK (analysis_file_count >= 0)
        """,
        "ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS engine_name text",
        "ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS engine_version text",
        "ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS rulepack_name text",
        "ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS rulepack_version text",
        "ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS ruleset_digest text",
        """
        ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS registered_rule_count
        integer CHECK (registered_rule_count >= 0)
        """,
        """
        ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS supported_rule_count
        integer CHECK (supported_rule_count >= 0)
        """,
    ):
        op.execute(statement)
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'scan_runs_progress_units_check'
                  AND conrelid = 'scan_runs'::regclass
            ) THEN
                ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_progress_units_check
                CHECK (total_units IS NULL OR completed_units <= total_units);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'scan_runs_completion_progress_check'
                  AND conrelid = 'scan_runs'::regclass
            ) THEN
                ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_completion_progress_check CHECK (
                    (status = 'COMPLETED' AND progress_percent = 100
                        AND total_units IS NOT NULL AND completed_units = total_units)
                    OR (status <> 'COMPLETED'
                        AND (progress_percent IS NULL OR progress_percent < 100))
                );
            END IF;
        END $$
        """
    )
    op.execute(
        """
        INSERT INTO projects (id, name, description)
        SELECT DISTINCT project_id, project_id, 'Migrated project'
        FROM scan_runs
        ON CONFLICT (id) DO NOTHING
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'scan_runs_project_id_fkey'
                  AND conrelid = 'scan_runs'::regclass
            ) THEN
                ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_project_id_fkey
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT;
            END IF;
        END $$
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_jobs (
            scan_id uuid PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
            status text NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
            worker_id text,
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            locked_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS scan_jobs_pending_idx
        ON scan_jobs (created_at) WHERE status = 'PENDING'
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS scan_runs_project_created_idx
        ON scan_runs (project_id, created_at DESC)
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_weakness_results (
            scan_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            weakness_id text NOT NULL,
            result jsonb NOT NULL,
            PRIMARY KEY (scan_id, weakness_id)
        )
        """
    )


def downgrade() -> None:
    raise RuntimeError("This adoption migration is intentionally irreversible")
