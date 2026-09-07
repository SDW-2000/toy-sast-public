"""Allow confirmed project deletion to remove owned scan history."""

from collections.abc import Sequence

from alembic import op

revision: str = "20260902_01"
down_revision: str | None = "20260901_04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


STRICT_CHILD_TRIGGER = """
CREATE OR REPLACE FUNCTION reject_completed_scan_child_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_scan_id uuid;
BEGIN
    target_scan_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.scan_id ELSE NEW.scan_id END;
    IF EXISTS (SELECT 1 FROM scan_runs WHERE id = target_scan_id AND status = 'COMPLETED') THEN
        RAISE EXCEPTION 'completed scan snapshots are immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND EXISTS (
        SELECT 1 FROM scan_runs WHERE id = OLD.scan_id AND status = 'COMPLETED'
    ) THEN
        RAISE EXCEPTION 'completed scan snapshots are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$
"""

STRICT_RUN_TRIGGER = """
CREATE OR REPLACE FUNCTION reject_completed_scan_run_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'COMPLETED' THEN
        RAISE EXCEPTION 'completed scan snapshots are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE deleted_scan_workspaces (
            scan_id uuid PRIMARY KEY,
            deleted_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_project_id_fkey;
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_project_id_fkey
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_completed_scan_child_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            target_scan_id uuid;
            cascade_project_id text;
        BEGIN
            cascade_project_id := current_setting('toy_sast.project_cascade_delete', true);
            IF TG_OP = 'DELETE' AND cascade_project_id <> '' AND EXISTS (
                SELECT 1 FROM scan_runs
                WHERE id = OLD.scan_id AND project_id = cascade_project_id
            ) THEN
                RETURN OLD;
            END IF;
            target_scan_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.scan_id ELSE NEW.scan_id END;
            IF EXISTS (
                SELECT 1 FROM scan_runs
                WHERE id = target_scan_id AND status = 'COMPLETED'
            ) THEN
                RAISE EXCEPTION 'completed scan snapshots are immutable';
            END IF;
            IF TG_OP = 'UPDATE' AND EXISTS (
                SELECT 1 FROM scan_runs WHERE id = OLD.scan_id AND status = 'COMPLETED'
            ) THEN
                RAISE EXCEPTION 'completed scan snapshots are immutable';
            END IF;
            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_completed_scan_run_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND current_setting(
                'toy_sast.project_cascade_delete', true
            ) = OLD.project_id THEN
                RETURN OLD;
            END IF;
            IF OLD.status = 'COMPLETED' THEN
                RAISE EXCEPTION 'completed scan snapshots are immutable';
            END IF;
            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END;
        $$
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE scan_runs DROP CONSTRAINT scan_runs_project_id_fkey;
        ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_project_id_fkey
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE RESTRICT
        """
    )
    op.execute(STRICT_CHILD_TRIGGER)
    op.execute(STRICT_RUN_TRIGGER)
    op.execute("DROP TABLE IF EXISTS deleted_scan_workspaces")
