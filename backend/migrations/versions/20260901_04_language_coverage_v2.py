"""Add non-destructive criterion-by-language result model v2."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260901_04"
down_revision: str | None = "20260901_03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_runs
        DROP CONSTRAINT scan_runs_issue_model_version_check,
        ADD CONSTRAINT scan_runs_issue_model_version_check
            CHECK (issue_model_version IS NULL OR issue_model_version IN (1, 2)),
        ADD COLUMN language_coverage_result_count integer
            CHECK (language_coverage_result_count >= 0)
        """
    )
    op.execute(
        """
        CREATE TABLE scan_language_results (
            scan_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            weakness_id text NOT NULL,
            weakness_number smallint NOT NULL CHECK (weakness_number BETWEEN 1 AND 49),
            language text NOT NULL CHECK (language IN ('Java', 'JavaScript', 'Python')),
            support_status text NOT NULL CHECK (
                support_status IN ('SUPPORTED', 'NOT_SUPPORTED')
            ),
            result_status text NOT NULL CHECK (
                result_status IN (
                    'DETECTED', 'NOT_DETECTED', 'NOT_SUPPORTED', 'CHECK_FAILED'
                )
            ),
            executed_rule_count integer NOT NULL CHECK (executed_rule_count >= 0),
            finding_count integer NOT NULL CHECK (finding_count >= 0),
            reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 4000),
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (scan_id, weakness_id, language),
            CONSTRAINT scan_language_results_identity_check CHECK (
                weakness_id = 'KISA-2021-' || lpad(weakness_number::text, 2, '0')
            ),
            CONSTRAINT scan_language_results_state_check CHECK (
                (
                    support_status = 'NOT_SUPPORTED'
                    AND result_status = 'NOT_SUPPORTED'
                    AND executed_rule_count = 0
                    AND finding_count = 0
                ) OR (
                    support_status = 'SUPPORTED'
                    AND executed_rule_count > 0
                    AND (
                        (result_status = 'DETECTED' AND finding_count > 0)
                        OR (result_status IN ('NOT_DETECTED', 'CHECK_FAILED')
                            AND finding_count = 0)
                    )
                )
            )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX scan_language_results_scan_order_idx
        ON scan_language_results (scan_id, weakness_number, language COLLATE "C")
        """
    )
    op.execute(
        """
        CREATE TRIGGER scan_language_results_completed_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON scan_language_results
        FOR EACH ROW EXECUTE FUNCTION reject_completed_scan_child_mutation()
        """
    )
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_issue_summary_check")
    op.execute(
        """
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_issue_summary_check CHECK (
            (
                issue_summary_version IS NULL
                AND coverage_result_count IS NULL
                AND language_coverage_result_count IS NULL
                AND issue_count IS NULL
                AND detected_issue_count IS NULL
                AND review_signal_count IS NULL
                AND issue_error_count IS NULL
                AND issue_warning_count IS NULL
                AND issue_info_count IS NULL
                AND issue_counts_by_weakness IS NULL
            ) OR (
                issue_summary_version = 1
                AND issue_model_version = 1
                AND coverage_result_count = 49
                AND language_coverage_result_count IS NULL
                AND issue_count BETWEEN 0 AND 10000
                AND issue_count = detected_issue_count + review_signal_count
                AND detected_issue_count =
                    issue_error_count + issue_warning_count + issue_info_count
                AND issue_error_count >= 0
                AND issue_warning_count >= 0
                AND issue_info_count >= 0
                AND jsonb_typeof(issue_counts_by_weakness) = 'object'
            ) OR (
                issue_summary_version = 2
                AND issue_model_version = 2
                AND coverage_result_count = 49
                AND language_coverage_result_count =
                    49 * jsonb_array_length(detected_languages)
                AND issue_count BETWEEN 0 AND 10000
                AND issue_count = detected_issue_count
                AND review_signal_count = 0
                AND detected_issue_count =
                    issue_error_count + issue_warning_count + issue_info_count
                AND issue_error_count >= 0
                AND issue_warning_count >= 0
                AND issue_info_count >= 0
                AND jsonb_typeof(issue_counts_by_weakness) = 'object'
            )
        )
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_issue_summary_check")
    op.execute(
        """
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_issue_summary_check CHECK (
            (
                issue_summary_version IS NULL
                AND coverage_result_count IS NULL
                AND issue_count IS NULL
                AND detected_issue_count IS NULL
                AND review_signal_count IS NULL
                AND issue_error_count IS NULL
                AND issue_warning_count IS NULL
                AND issue_info_count IS NULL
                AND issue_counts_by_weakness IS NULL
            ) OR (
                issue_summary_version = 1
                AND issue_model_version = 1
                AND coverage_result_count = 49
                AND issue_count BETWEEN 0 AND 10000
                AND issue_count = detected_issue_count + review_signal_count
                AND detected_issue_count =
                    issue_error_count + issue_warning_count + issue_info_count
                AND issue_error_count >= 0
                AND issue_warning_count >= 0
                AND issue_info_count >= 0
                AND jsonb_typeof(issue_counts_by_weakness) = 'object'
            )
        )
        """
    )
    op.execute("DROP TRIGGER scan_language_results_completed_immutable ON scan_language_results")
    op.execute("DROP TABLE scan_language_results")
    op.execute(
        """
        ALTER TABLE scan_runs
        DROP COLUMN language_coverage_result_count,
        DROP CONSTRAINT scan_runs_issue_model_version_check,
        ADD CONSTRAINT scan_runs_issue_model_version_check
            CHECK (issue_model_version IS NULL OR issue_model_version = 1)
        """
    )
