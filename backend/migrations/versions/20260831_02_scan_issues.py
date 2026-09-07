"""Add the normalized issue-first result model."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260831_02"
down_revision: str | None = "20260831_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_runs
        ADD COLUMN issue_model_version smallint
        """
    )
    op.execute(
        """
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_issue_model_version_check
        CHECK (issue_model_version IS NULL OR issue_model_version = 1)
        """
    )
    op.execute(
        """
        CREATE TABLE scan_issues (
            issue_id uuid PRIMARY KEY,
            scan_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            fingerprint char(64) NOT NULL,
            fingerprint_version smallint NOT NULL CHECK (fingerprint_version = 1),
            result_status text NOT NULL CHECK (
                result_status IN ('DETECTED', 'REVIEW_REQUIRED')
            ),
            finding_kind text NOT NULL CHECK (
                finding_kind IN ('DETECTED', 'REVIEW_SIGNAL')
            ),
            severity text NOT NULL CHECK (severity IN ('ERROR', 'WARNING', 'INFO')),
            weakness_id text NOT NULL,
            weakness_number smallint NOT NULL CHECK (weakness_number BETWEEN 1 AND 49),
            weakness_name text NOT NULL,
            weakness_category text NOT NULL,
            weakness_category_number smallint NOT NULL CHECK (weakness_category_number > 0),
            weakness_description text NOT NULL,
            sast_classification text NOT NULL CHECK (
                sast_classification IN ('AUTO', 'PARTIAL', 'MANUAL')
            ),
            implementation_status text NOT NULL CHECK (
                implementation_status IN (
                    'IMPLEMENTED', 'PARTIALLY_IMPLEMENTED',
                    'MANUAL_REVIEW_REQUIRED', 'NOT_IMPLEMENTED'
                )
            ),
            rule_id text NOT NULL,
            language text NOT NULL CHECK (language IN ('Java', 'JavaScript', 'Python')),
            path text NOT NULL,
            start_line integer NOT NULL CHECK (start_line > 0),
            start_column integer NOT NULL CHECK (start_column > 0),
            end_line integer NOT NULL CHECK (end_line > 0),
            end_column integer NOT NULL CHECK (end_column > 0),
            message text NOT NULL CHECK (char_length(message) BETWEEN 1 AND 4000),
            rule_description text,
            cwe_id text,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT scan_issues_fingerprint_unique UNIQUE (scan_id, fingerprint),
            CONSTRAINT scan_issues_status_kind_check CHECK (
                (finding_kind = 'DETECTED' AND result_status = 'DETECTED')
                OR (finding_kind = 'REVIEW_SIGNAL' AND result_status = 'REVIEW_REQUIRED')
            ),
            CONSTRAINT scan_issues_location_check CHECK (
                end_line > start_line
                OR (end_line = start_line AND end_column >= start_column)
            ),
            CONSTRAINT scan_issues_path_check CHECK (
                octet_length(path) BETWEEN 1 AND 4096
            ),
            CONSTRAINT scan_issues_target_file_fkey
                FOREIGN KEY (scan_id, path)
                REFERENCES scan_files(scan_id, path)
                DEFERRABLE INITIALLY DEFERRED
        )
        """
    )
    op.execute(
        """
        CREATE INDEX scan_issues_order_idx ON scan_issues (
            scan_id, weakness_number, path COLLATE "C",
            start_line, start_column, issue_id
        )
        """
    )
    op.execute(
        """
        CREATE INDEX scan_issues_filters_idx ON scan_issues (
            scan_id, result_status, severity, language, weakness_id
        )
        """
    )
    op.execute(
        """
        CREATE INDEX scan_issues_path_idx
        ON scan_issues (scan_id, path text_pattern_ops)
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE scan_issues")
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_issue_model_version_check")
    op.execute("ALTER TABLE scan_runs DROP COLUMN issue_model_version")
