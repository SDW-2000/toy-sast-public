"""Freeze completed snapshots and persist bounded integrity summaries."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260901_01"
down_revision: str | None = "20260831_02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_runs
        ADD COLUMN manifest_summary_version smallint,
        ADD COLUMN manifest_root_count integer,
        ADD COLUMN manifest_directory_count integer,
        ADD COLUMN manifest_file_count integer,
        ADD COLUMN manifest_finding_count integer,
        ADD COLUMN issue_summary_version smallint,
        ADD COLUMN coverage_result_count smallint,
        ADD COLUMN issue_count integer,
        ADD COLUMN detected_issue_count integer,
        ADD COLUMN review_signal_count integer,
        ADD COLUMN issue_error_count integer,
        ADD COLUMN issue_warning_count integer,
        ADD COLUMN issue_info_count integer,
        ADD COLUMN issue_counts_by_weakness jsonb
        """
    )
    op.execute(
        """
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_manifest_summary_check CHECK (
            (
                manifest_summary_version IS NULL
                AND manifest_root_count IS NULL
                AND manifest_directory_count IS NULL
                AND manifest_file_count IS NULL
                AND manifest_finding_count IS NULL
            )
            OR (
                manifest_summary_version = 1
                AND manifest_version = 1
                AND manifest_node_count IS NOT NULL
                AND manifest_root_count IS NOT NULL
                AND manifest_directory_count IS NOT NULL
                AND manifest_file_count IS NOT NULL
                AND manifest_finding_count IS NOT NULL
                AND archive_file_count IS NOT NULL
                AND manifest_node_count = manifest_directory_count + manifest_file_count
                AND manifest_root_count BETWEEN 1 AND manifest_node_count
                AND manifest_directory_count >= 0
                AND manifest_file_count = archive_file_count
                AND manifest_finding_count >= 0
            )
        )
        """
    )
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
            )
            OR (
                issue_summary_version = 1
                AND issue_model_version = 1
                AND coverage_result_count IS NOT NULL
                AND issue_count IS NOT NULL
                AND detected_issue_count IS NOT NULL
                AND review_signal_count IS NOT NULL
                AND issue_error_count IS NOT NULL
                AND issue_warning_count IS NOT NULL
                AND issue_info_count IS NOT NULL
                AND issue_counts_by_weakness IS NOT NULL
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

    # The earlier migrations only allowed these snapshots to be created after complete
    # application validation. Backfill compact summaries before freezing those rows.
    op.execute(
        """
        UPDATE scan_runs AS run
        SET manifest_summary_version = 1,
            manifest_root_count = summary.root_count,
            manifest_directory_count = summary.directory_count,
            manifest_file_count = summary.file_count,
            manifest_finding_count = summary.finding_count
        FROM (
            SELECT
                scan_id,
                count(*) FILTER (WHERE parent_path IS NULL)::integer AS root_count,
                count(*) FILTER (WHERE node_type = 'DIRECTORY')::integer
                    AS directory_count,
                count(*) FILTER (WHERE node_type = 'FILE')::integer AS file_count,
                coalesce(sum(finding_count) FILTER (WHERE node_type = 'FILE'), 0)::integer
                    AS finding_count
            FROM scan_files
            GROUP BY scan_id
        ) AS summary
        WHERE run.id = summary.scan_id AND run.manifest_version = 1
        """
    )
    op.execute(
        """
        UPDATE scan_runs AS run
        SET issue_summary_version = 1,
            coverage_result_count = summary.coverage_count,
            issue_count = summary.issue_count,
            detected_issue_count = summary.detected_count,
            review_signal_count = summary.review_count,
            issue_error_count = summary.error_count,
            issue_warning_count = summary.warning_count,
            issue_info_count = summary.info_count,
            issue_counts_by_weakness = summary.counts_by_weakness
        FROM (
            SELECT
                run_id AS scan_id,
                coverage_count,
                issue_count,
                detected_count,
                review_count,
                error_count,
                warning_count,
                info_count,
                counts_by_weakness
            FROM (
                SELECT
                    current_run.id AS run_id,
                    (SELECT count(*) FROM scan_weakness_results AS coverage
                     WHERE coverage.scan_id = current_run.id)::smallint AS coverage_count,
                    (SELECT count(*) FROM scan_issues AS issue
                     WHERE issue.scan_id = current_run.id)::integer AS issue_count,
                    (SELECT count(*) FROM scan_issues AS issue
                     WHERE issue.scan_id = current_run.id
                       AND issue.result_status = 'DETECTED')::integer AS detected_count,
                    (SELECT count(*) FROM scan_issues AS issue
                     WHERE issue.scan_id = current_run.id
                       AND issue.result_status = 'REVIEW_REQUIRED')::integer AS review_count,
                    (SELECT count(*) FROM scan_issues AS issue
                     WHERE issue.scan_id = current_run.id
                       AND issue.result_status = 'DETECTED'
                       AND issue.severity = 'ERROR')::integer AS error_count,
                    (SELECT count(*) FROM scan_issues AS issue
                     WHERE issue.scan_id = current_run.id
                       AND issue.result_status = 'DETECTED'
                       AND issue.severity = 'WARNING')::integer AS warning_count,
                    (SELECT count(*) FROM scan_issues AS issue
                     WHERE issue.scan_id = current_run.id
                       AND issue.result_status = 'DETECTED'
                       AND issue.severity = 'INFO')::integer AS info_count,
                    coalesce(
                        (SELECT jsonb_object_agg(counts.weakness_id, counts.issue_count)
                         FROM (
                             SELECT issue.weakness_id, count(*)::integer AS issue_count
                             FROM scan_issues AS issue
                             WHERE issue.scan_id = current_run.id
                             GROUP BY issue.weakness_id
                         ) AS counts),
                        '{}'::jsonb
                    ) AS counts_by_weakness
                FROM scan_runs AS current_run
                WHERE current_run.issue_model_version = 1
            ) AS calculated
        ) AS summary
        WHERE run.id = summary.scan_id
        """
    )

    op.execute(
        """
        CREATE FUNCTION reject_completed_scan_child_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE target_scan_id uuid;
        BEGIN
            target_scan_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.scan_id ELSE NEW.scan_id END;
            IF EXISTS (
                SELECT 1 FROM scan_runs
                WHERE id = target_scan_id AND status = 'COMPLETED'
            ) THEN
                RAISE EXCEPTION 'completed scan snapshots are immutable';
            END IF;
            IF TG_OP = 'UPDATE' AND EXISTS (
                SELECT 1 FROM scan_runs
                WHERE id = OLD.scan_id AND status = 'COMPLETED'
            ) THEN
                RAISE EXCEPTION 'completed scan snapshots are immutable';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    for table in ("scan_files", "scan_issues", "scan_weakness_results"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_completed_immutable
            BEFORE INSERT OR UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_completed_scan_child_mutation()
            """
        )
    op.execute(
        """
        CREATE FUNCTION reject_completed_scan_run_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.status = 'COMPLETED' THEN
                RAISE EXCEPTION 'completed scan snapshots are immutable';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER scan_runs_completed_immutable
        BEFORE UPDATE OR DELETE ON scan_runs
        FOR EACH ROW EXECUTE FUNCTION reject_completed_scan_run_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER scan_runs_completed_immutable ON scan_runs")
    op.execute("DROP FUNCTION reject_completed_scan_run_mutation()")
    for table in ("scan_weakness_results", "scan_issues", "scan_files"):
        op.execute(f"DROP TRIGGER {table}_completed_immutable ON {table}")
    op.execute("DROP FUNCTION reject_completed_scan_child_mutation()")
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_issue_summary_check")
    op.execute("ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_manifest_summary_check")
    op.execute(
        """
        ALTER TABLE scan_runs
        DROP COLUMN issue_counts_by_weakness,
        DROP COLUMN issue_info_count,
        DROP COLUMN issue_warning_count,
        DROP COLUMN issue_error_count,
        DROP COLUMN review_signal_count,
        DROP COLUMN detected_issue_count,
        DROP COLUMN issue_count,
        DROP COLUMN coverage_result_count,
        DROP COLUMN issue_summary_version,
        DROP COLUMN manifest_finding_count,
        DROP COLUMN manifest_file_count,
        DROP COLUMN manifest_directory_count,
        DROP COLUMN manifest_root_count,
        DROP COLUMN manifest_summary_version
        """
    )
