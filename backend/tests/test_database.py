from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from app import database as database_module
from app.analyzer import issue_id_for, normalize_issues, normalize_results
from app.database import (
    SCHEMA_REVISION,
    CorruptScanIssueModelError,
    CorruptScanManifestError,
    Database,
    InvalidIssuesCursorError,
    InvalidScanFilesCursorError,
    IssueFilters,
    ProjectNotFoundError,
    ScanFileParentNotFoundError,
    ScanFilesNotReadyError,
    ScanSnapshotConflictError,
    SchemaNotReadyError,
    StaleScanLeaseError,
    _issue_filter_sql,
    _issue_guidance_snapshot,
)
from app.rule_registry import RULEPACK_VERSION, validate_rulepack_manifest
from app.schemas import IssuePathScope, IssueStats, JsonObject, ScanFileNode

PACKAGED_RULEPACK_MANIFEST = validate_rulepack_manifest(
    Path(__file__).resolve().parents[2] / "analyzer" / "rules"
)


def python_manifest_node(*, path: str = "app.py", finding_count: int = 0) -> ScanFileNode:
    return ScanFileNode(
        path=path,
        parent_path=None,
        name=path,
        depth=1,
        entry_type="FILE",
        size_bytes=1,
        language="Python",
        analysis_state="TARGET",
        finding_count=finding_count,
        has_children=False,
    )


def test_complete_scan_rejects_duplicate_weakness_ids_before_database_write() -> None:
    duplicate_results: list[JsonObject] = [{"weakness_id": "KISA-2021-01"} for _ in range(49)]

    with pytest.raises(ValueError, match="exactly once"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=[],
            results=duplicate_results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_alembic_adoption_revision_emits_safe_schema_adoption_without_snapshot_backfill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend_root = Path(__file__).resolve().parents[1]
    configuration = Config(str(backend_root / "alembic.ini"))
    scripts = ScriptDirectory.from_config(configuration)

    assert scripts.get_heads() == [SCHEMA_REVISION]
    invitation_revision = scripts.get_revision(SCHEMA_REVISION)
    assert invitation_revision is not None
    assert invitation_revision.down_revision == "20260902_02"
    assert Path(invitation_revision.path).is_file()
    auth_revision = scripts.get_revision("20260902_02")
    assert auth_revision is not None
    assert auth_revision.down_revision == "20260902_01"

    adoption_revision = scripts.get_revision("20260830_01")
    assert adoption_revision is not None
    assert adoption_revision.down_revision is None

    statements: list[str] = []
    migration_module = cast(Any, adoption_revision.module)
    monkeypatch.setattr(migration_module.op, "execute", statements.append)
    migration_module.upgrade()
    emitted_sql = "\n".join(statements)

    assert "ADD COLUMN IF NOT EXISTS supported_rule_count" in emitted_sql
    assert "ADD COLUMN IF NOT EXISTS rulepack_version" in emitted_sql
    assert "rulepack_version text NOT NULL" not in emitted_sql
    assert "supported_rule_count integer NOT NULL" not in emitted_sql
    assert "legacy-smoke" not in emitted_sql
    assert "UPDATE scan_runs SET rulepack_version" not in emitted_sql
    assert "UPDATE scan_weakness_results" not in emitted_sql
    assert "INSERT INTO projects" in emitted_sql
    assert "FOREIGN KEY (project_id)" in emitted_sql
    assert emitted_sql.index("INSERT INTO projects") < emitted_sql.index("FOREIGN KEY (project_id)")

    manifest_statements: list[str] = []
    manifest_revision = scripts.get_revision("20260831_01")
    assert manifest_revision is not None
    manifest_module = cast(Any, manifest_revision.module)
    monkeypatch.setattr(manifest_module.op, "execute", manifest_statements.append)
    manifest_module.upgrade()
    manifest_sql = "\n".join(manifest_statements)
    assert "CREATE TABLE scan_files" in manifest_sql
    assert "DEFERRABLE INITIALLY DEFERRED" in manifest_sql
    assert "manifest_version" in manifest_sql
    assert "manifest_node_count" in manifest_sql
    assert "archive_data" not in manifest_sql

    issue_statements: list[str] = []
    issue_revision = scripts.get_revision("20260831_02")
    assert issue_revision is not None
    issue_module = cast(Any, issue_revision.module)
    monkeypatch.setattr(issue_module.op, "execute", issue_statements.append)
    issue_module.upgrade()
    issue_sql = "\n".join(issue_statements)
    assert "CREATE TABLE scan_issues" in issue_sql
    assert "issue_model_version" in issue_sql
    assert "source" not in issue_sql.casefold()

    summary_statements: list[str] = []
    summary_revision = scripts.get_revision("20260901_01")
    assert summary_revision is not None
    summary_module = cast(Any, summary_revision.module)
    monkeypatch.setattr(summary_module.op, "execute", summary_statements.append)
    summary_module.upgrade()
    summary_sql = "\n".join(summary_statements)
    assert "manifest_summary_version" in summary_sql
    assert "issue_summary_version" in summary_sql
    assert "coverage_result_count = 49" in summary_sql
    assert "completed scan snapshots are immutable" in summary_sql

    guidance_statements: list[str] = []
    guidance_revision = scripts.get_revision("20260901_02")
    assert guidance_revision is not None
    guidance_module = cast(Any, guidance_revision.module)
    monkeypatch.setattr(guidance_module.op, "execute", guidance_statements.append)
    guidance_module.upgrade()
    guidance_sql = "\n".join(guidance_statements)
    assert guidance_sql.count("scan_issues_completed_immutable") == 2
    assert "ALTER COLUMN automation_limitation SET NOT NULL" in guidance_sql
    assert "manual_verification_checks" in guidance_sql
    assert "safe_implementation_example" in guidance_sql
    assert "https://cwe.mitre.org/data/definitions/" in guidance_sql
    assert "https://cwe.mitre.org/data/index.html" in guidance_sql

    detection_statements: list[str] = []
    detection_revision = scripts.get_revision("20260901_03")
    assert detection_revision is not None
    detection_module = cast(Any, detection_revision.module)
    monkeypatch.setattr(detection_module.op, "execute", detection_statements.append)
    detection_module.upgrade()
    detection_sql = "\n".join(detection_statements)
    assert detection_sql.count("scan_issues_completed_immutable") == 2
    assert "UPDATE scan_issues" in detection_sql
    assert "detection_basis_version = 1" in detection_sql
    assert "WHEN 'DETECTED' THEN 'MEDIUM'" in detection_sql
    assert "ELSE 'LOW'" in detection_sql
    assert "WITH normalized_fragments AS" in detection_sql
    assert "regexp_replace(" in detection_sql
    assert "'[.!?。！？]+$', ''" in detection_sql
    assert "coalesce(nullif(rule_description, ''), '정보 없음')" in detection_sql
    assert "IN ('.', '!', '?', '。', '！', '？')" in detection_sql
    assert "normalized.rule_description_sentence" in detection_sql
    assert "normalized.message_sentence" in detection_sql
    assert "'. 탐지 메시지: '" not in detection_sql
    assert "ALTER COLUMN detection_rationale SET NOT NULL" in detection_sql
    assert "char_length(detection_rationale) BETWEEN 1 AND 4000" in detection_sql
    assert "confidence IN ('MEDIUM', 'LOW')" in detection_sql

    v2_revision = scripts.get_revision("20260901_04")
    assert v2_revision is not None
    v2_statements: list[str] = []
    v2_module = cast(Any, v2_revision.module)
    monkeypatch.setattr(v2_module.op, "execute", v2_statements.append)
    v2_module.upgrade()
    v2_sql = "\n".join(v2_statements)
    assert "CREATE TABLE scan_language_results" in v2_sql
    assert "issue_model_version IN (1, 2)" in v2_sql
    assert "REVIEW_REQUIRED" not in v2_sql
    assert "language_coverage_result_count" in v2_sql

    cascade_revision = scripts.get_revision("20260902_01")
    assert cascade_revision is not None
    cascade_statements: list[str] = []
    cascade_module = cast(Any, cascade_revision.module)
    monkeypatch.setattr(cascade_module.op, "execute", cascade_statements.append)
    cascade_module.upgrade()
    cascade_sql = "\n".join(cascade_statements)
    assert "CREATE TABLE deleted_scan_workspaces" in cascade_sql
    assert "ON DELETE CASCADE" in cascade_sql
    assert "current_setting('toy_sast.project_cascade_delete', true)" in cascade_sql

    auth_statements: list[str] = []
    auth_module = cast(Any, auth_revision.module)
    monkeypatch.setattr(auth_module.op, "execute", auth_statements.append)
    auth_module.upgrade()
    auth_sql = "\n".join(auth_statements)
    assert "CREATE TABLE users" in auth_sql
    assert "CREATE TABLE project_members" in auth_sql
    assert "CREATE TABLE sessions" in auth_sql
    assert "ON DELETE CASCADE" in auth_sql


class ScriptedCursor:
    def __init__(self, rows: list[dict[str, object] | None]) -> None:
        self.rows = rows
        self.calls: list[str] = []
        self.parameters: list[object] = []
        self.rowcount = 1

    def __enter__(self) -> "ScriptedCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, _parameters: object = None) -> None:
        self.calls.append(statement)
        self.parameters.append(_parameters)

    def fetchone(self) -> dict[str, object] | None:
        return self.rows.pop(0)

    def fetchall(self) -> list[dict[str, object]]:
        return []


class ScriptedConnection:
    def __init__(self, cursor: ScriptedCursor) -> None:
        self.scripted_cursor = cursor

    def __enter__(self) -> "ScriptedConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> ScriptedCursor:
        return self.scripted_cursor


class ProjectMemberCursor:
    def __init__(
        self,
        *,
        existing_user_ids: list[str],
        users: list[dict[str, object]],
    ) -> None:
        self.existing_user_ids = existing_user_ids
        self.users = users
        self.result_rows: list[dict[str, object]] = []
        self.inserted: list[tuple[str, str]] = []

    def execute(self, statement: str, _parameters: object = None) -> None:
        if "SELECT user_id::text" in statement:
            self.result_rows = [{"user_id": user_id} for user_id in self.existing_user_ids]
        elif "SELECT id::text AS id, is_active" in statement:
            self.result_rows = self.users
        else:
            self.result_rows = []

    def fetchall(self) -> list[dict[str, object]]:
        return self.result_rows

    def executemany(self, _statement: str, parameters: list[tuple[str, str]]) -> None:
        self.inserted.extend(parameters)


def test_project_members_allow_an_existing_inactive_user_to_remain_assigned() -> None:
    cursor = ProjectMemberCursor(
        existing_user_ids=["inactive-user"],
        users=[{"id": "inactive-user", "is_active": False}],
    )

    Database._replace_project_members_with_cursor(cursor, "project-id", ["inactive-user"])

    assert cursor.inserted == [("project-id", "inactive-user")]


def test_project_members_reject_a_new_inactive_user() -> None:
    cursor = ProjectMemberCursor(
        existing_user_ids=[],
        users=[{"id": "inactive-user", "is_active": False}],
    )

    with pytest.raises(database_module.InvalidProjectMembersError):
        Database._replace_project_members_with_cursor(cursor, "project-id", ["inactive-user"])


def test_ensure_schema_only_asserts_current_alembic_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([{"to_regclass": "alembic_version"}, {"version_num": SCHEMA_REVISION}])
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    database.ensure_schema()

    assert database._schema_ready is True
    assert all(
        "CREATE " not in statement and "ALTER " not in statement for statement in cursor.calls
    )


def test_ensure_schema_rejects_unmigrated_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([{"to_regclass": None}])
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    with pytest.raises(SchemaNotReadyError, match="migrations"):
        database.ensure_schema()


def test_user_activation_update_is_limited_to_normal_users(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([None])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    assert database.set_user_active("user-id", False) is None
    assert "role = 'USER'" in cursor.calls[0]


def test_session_creation_locks_an_active_user_before_inserting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    cursor = ScriptedCursor(
        [
            {
                "id": "user-id",
                "email": "user@example.com",
                "role": "USER",
                "is_active": True,
                "created_at": now,
                "updated_at": now,
            },
            {"expires_at": now + timedelta(hours=1)},
        ]
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    session = database.create_session("a" * 64, "user-id", expires_at=now + timedelta(hours=1))

    assert session.id == "user-id"
    assert "FOR SHARE" in cursor.calls[0]
    assert "INSERT INTO sessions" in cursor.calls[2]


def test_delete_project_uses_the_database_cascade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([{"id": "project-id"}, None])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    assert database.delete_project("project-id") is True
    assert cursor.calls == [
        "SELECT id FROM projects WHERE id = %s FOR UPDATE",
        """
                    SELECT id FROM scan_runs
                    WHERE project_id = %s AND status IN ('PENDING', 'RUNNING')
                    LIMIT 1 FOR UPDATE
                    """,
        """
                    INSERT INTO deleted_scan_workspaces (scan_id)
                    SELECT id FROM scan_runs WHERE project_id = %s
                    ON CONFLICT (scan_id) DO NOTHING
                    """,
        "SELECT set_config('toy_sast.project_cascade_delete', %s, true)",
        "DELETE FROM projects WHERE id = %s",
    ]
    assert cursor.parameters == [
        ("project-id",),
        ("project-id",),
        ("project-id",),
        ("project-id",),
        ("project-id",),
    ]


def test_delete_project_rejects_an_active_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([{"id": "project-id"}, {"id": "scan-id"}])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    with pytest.raises(database_module.ProjectHasActiveScansError):
        database.delete_project("project-id")

    assert len(cursor.calls) == 2


def test_delete_project_returns_false_when_project_does_not_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([None])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    assert database.delete_project("missing") is False
    assert cursor.calls == ["SELECT id FROM projects WHERE id = %s FOR UPDATE"]


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"reapable": True}, True),
        ({"reapable": False}, False),
        (None, False),
    ],
)
def test_scan_workspace_reapability_requires_both_terminal_records(
    monkeypatch: pytest.MonkeyPatch, row: dict[str, object] | None, expected: bool
) -> None:
    cursor = ScriptedCursor([row])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    assert database.is_scan_workspace_reapable("11111111-1111-1111-1111-111111111111") is expected
    assert "run.status = 'COMPLETED' AND job.status = 'COMPLETED'" in cursor.calls[0]
    assert "run.status = 'FAILED' AND job.status = 'FAILED'" in cursor.calls[0]
    assert "deleted_scan_workspaces" in cursor.calls[0]


def test_create_scan_atomically_rejects_unknown_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([None])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    with pytest.raises(ProjectNotFoundError):
        database.create_scan("scan-id", "missing", "source.zip", b"PK")

    assert len(cursor.calls) == 1
    assert "FOR SHARE" in cursor.calls[0]


def test_project_search_and_latest_language_filter_are_parameterized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([{"total": 0}])
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    result = database.list_projects(
        query="  %' OR true --  ",
        language=" Python ",
        limit=25,
        offset=50,
    )

    assert result.total == 0
    assert result.items == []
    assert len(cursor.calls) == 2
    assert all("%' OR true --" not in statement for statement in cursor.calls)
    assert "latest_scan.detected_languages ? %s::text" in cursor.calls[0]
    assert "scan.archive_data" not in cursor.calls[1]
    expected_filters = ("%' OR true --", "%' OR true --", "Python", "Python")
    assert cursor.parameters == [
        (*expected_filters, None, None),
        (*expected_filters, None, None, 25, 50),
    ]


def test_progress_rejects_completed_units_above_total_before_database_write() -> None:
    with pytest.raises(ValueError, match="completed <= total"):
        Database("postgresql://unused:unused@localhost/unused").update_progress(
            "scan-id",
            worker_id="worker",
            attempt=1,
            phase="ANALYZING",
            completed_units=3,
            total_units=2,
            message="invalid",
        )


def test_target_metadata_rejects_language_count_mismatch_before_database_write() -> None:
    with pytest.raises(ValueError, match="sum"):
        Database("postgresql://unused:unused@localhost/unused").record_target_metadata(
            "scan-id",
            worker_id="worker",
            attempt=1,
            archive_file_count=2,
            analysis_file_count=2,
            detected_languages=["Python"],
            language_file_counts={"Python": 1},
            executed_rule_count=27,
        )


@pytest.mark.parametrize(
    ("detected_languages", "language_file_counts", "analysis_file_count", "rule_count", "error"),
    [
        (["Python"], {"Python": -1}, 1, 27, "positive integers"),
        (["Python"], {"Python": 0}, 0, 27, "positive integers"),
        (["Python"], {"Python": 1.5}, 1, 27, "positive integers"),
        (["Python"], {"Python": "1"}, 1, 27, "positive integers"),
        (["Python"], {"Python": True}, 1, 27, "positive integers"),
        (["Python", "Python"], {"Python": 2}, 2, 27, "duplicates"),
        (["Ruby"], {"Ruby": 1}, 1, 0, "supported language names"),
        (["Python"], {"Python": 1, "Ruby": 1}, 2, 27, "supported language names"),
        ([], {}, 0, -1, "executed rule count"),
    ],
)
def test_target_metadata_rejects_invalid_language_metadata_before_database_write(
    detected_languages: list[str],
    language_file_counts: dict[str, Any],
    analysis_file_count: int,
    rule_count: int,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        Database("postgresql://unused:unused@localhost/unused").record_target_metadata(
            "scan-id",
            worker_id="worker",
            attempt=1,
            archive_file_count=max(analysis_file_count, 0),
            analysis_file_count=analysis_file_count,
            detected_languages=detected_languages,
            language_file_counts=cast(dict[str, int], language_file_counts),
            executed_rule_count=rule_count,
        )


def test_target_metadata_accepts_empty_language_snapshot_for_archive_without_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([])
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    database.record_target_metadata(
        "scan-id",
        worker_id="worker",
        attempt=1,
        archive_file_count=2,
        analysis_file_count=0,
        detected_languages=[],
        language_file_counts={},
        executed_rule_count=0,
    )

    assert len(cursor.calls) == 1
    assert "language_file_counts = %s" in cursor.calls[0]


def test_snapshot_write_fails_closed_on_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = ScriptedCursor([])
    cursor.rowcount = 0
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    with pytest.raises(ScanSnapshotConflictError, match="immutable engine snapshot"):
        database.record_engine_snapshot(
            "scan-id",
            worker_id="worker",
            attempt=2,
            engine_name="Semgrep",
            engine_version="1.174.0",
            rulepack_name="KISA 2021 SAST",
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_validates_catalog_metadata_before_database_write() -> None:
    results = normalize_results([], ["Python"])
    results[0]["name"] = "tampered"

    with pytest.raises(ValueError, match="catalog metadata mismatch"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_validates_finding_count_before_database_write() -> None:
    results = normalize_results([], ["Python"])
    results[1]["finding_count"] = 1

    with pytest.raises(ValueError, match="finding_count"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_manual_review_status_promotion() -> None:
    results = normalize_results([], ["JavaScript"])
    manual_result = results[17]
    manual_result["support_status"] = "SUPPORTED"
    manual_result["result_status"] = "DETECTED"

    with pytest.raises(ValueError, match="manual review criteria"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["JavaScript"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_validates_finding_rule_metadata_before_database_write() -> None:
    results = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "app.py"}],
        ["Python"],
    )
    findings = cast(list[JsonObject], results[1]["findings"])
    findings[0]["rule_id"] = "kisa-2021-05-python-os-command-injection"

    with pytest.raises(ValueError, match="finding rule metadata mismatch"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_detected_result_without_findings() -> None:
    results = normalize_results([], ["Python"])
    results[1]["result_status"] = "DETECTED"

    with pytest.raises(ValueError, match="DETECTED results"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_state_that_ignores_active_partial_rules() -> None:
    results = normalize_results([], ["Python"])
    results[1]["support_status"] = "NOT_SUPPORTED"
    results[1]["result_status"] = "NOT_SUPPORTED"

    with pytest.raises(ValueError, match="invalid support/result state"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_finding_language_outside_detected_languages() -> None:
    results = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"}],
        ["Python"],
    )

    with pytest.raises(ValueError, match="finding language mismatch"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Java"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_absolute_finding_path() -> None:
    results = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "/work/src/app.py"}],
        ["Python"],
    )

    with pytest.raises(ValueError, match="workspace-relative"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_review_signal_kind_on_automated_rule() -> None:
    results = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"}],
        ["Python"],
    )
    findings = cast(list[JsonObject], results[1]["findings"])
    findings[0]["kind"] = "REVIEW_SIGNAL"

    with pytest.raises(ValueError, match="automated criteria"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


def test_complete_scan_rejects_results_out_of_catalog_order() -> None:
    results = normalize_results([], ["Python"])
    results[0], results[1] = results[1], results[0]

    with pytest.raises(ValueError, match="exactly once in order"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-001",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        )


class StaleLeaseCursor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...] | None]] = []

    def __enter__(self) -> "StaleLeaseCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: tuple[object, ...] | None = None) -> None:
        self.calls.append((statement, parameters))

    def fetchone(self) -> None:
        return None


class StaleLeaseConnection:
    def __init__(self, cursor: StaleLeaseCursor) -> None:
        self.stale_cursor = cursor

    def __enter__(self) -> "StaleLeaseConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> StaleLeaseCursor:
        return self.stale_cursor


def test_progress_update_fails_closed_for_stale_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = StaleLeaseCursor()
    connection = StaleLeaseConnection(cursor)
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, connection))

    with pytest.raises(StaleScanLeaseError, match="no longer owned"):
        database.update_progress(
            "scan-id",
            worker_id="worker-a",
            attempt=1,
            phase="ANALYZING",
            completed_units=1,
            total_units=2,
            message="working",
        )

    assert len(cursor.calls) == 1
    assert cursor.calls[0][1] == ("scan-id", "worker-a", 1)


def test_scan_lease_heartbeat_refreshes_only_the_owned_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ScriptedCursor([{"scan_id": "scan-id"}])
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ScriptedConnection(cursor)))

    database.renew_scan_lease("scan-id", worker_id="worker-a", attempt=2)

    assert "SET locked_at = now()" in cursor.calls[0]
    assert cursor.parameters == [("scan-id", "worker-a", 2)]


class CompletionCursor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...] | None]] = []
        self.inserted_batches: list[list[tuple[object, ...]]] = []
        self.rowcount = 1
        self.fetchone_count = 0

    def __enter__(self) -> "CompletionCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: tuple[object, ...] | None = None) -> None:
        self.calls.append((statement, parameters))
        self.rowcount = 1

    def executemany(self, statement: str, parameters: list[tuple[object, ...]]) -> None:
        self.calls.append((statement, None))
        self.inserted_batches.append(parameters)

    def fetchone(self) -> dict[str, object]:
        self.fetchone_count += 1
        if self.fetchone_count == 1:
            return {
                "archive_file_count": 1,
                "analysis_file_count": 1,
                "detected_languages": ["Python"],
                "language_file_counts": {"Python": 1},
                "engine_name": "Semgrep",
                "engine_version": "1.174.0",
                "rulepack_name": "KISA 2021 SAST",
                "rulepack_version": PACKAGED_RULEPACK_MANIFEST.version,
                "ruleset_digest": PACKAGED_RULEPACK_MANIFEST.digest,
                "registered_rule_count": len(PACKAGED_RULEPACK_MANIFEST.rule_ids),
                "supported_rule_count": 25,
                "total_units": 1,
                "completed_units": 0,
                "archive_data": b"PK",
                "manifest_version": None,
                "manifest_node_count": None,
            }
        if self.fetchone_count == 2:
            return {"has_results": False, "has_manifest": False}
        return {"scan_id": "scan-id"}


class CompletionConnection:
    def __init__(self, cursor: CompletionCursor) -> None:
        self.completion_cursor = cursor

    def __enter__(self) -> "CompletionConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> CompletionCursor:
        return self.completion_cursor


def test_complete_scan_persists_rulepack_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = CompletionCursor()
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(
        database,
        "_connect",
        lambda: cast(Any, CompletionConnection(cursor)),
    )

    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    semgrep_results = [
        {
            "check_id": "kisa-2021-02-python-code-injection",
            "path": "app.py",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 5},
            "extra": {"message": "detected", "severity": "ERROR"},
        }
    ]
    database.complete_scan(
        scan_id,
        worker_id="worker-a",
        attempt=1,
        detected_languages=["Python"],
        results=normalize_results(semgrep_results, ["Python"]),
        rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
        issues=normalize_issues(semgrep_results, ["Python"]),
        manifest_nodes=[python_manifest_node(finding_count=1)],
        completion_message="분석이 완료되었지만 일부 파일에 부분 해석 경고가 있습니다.",
    )

    completion_parameters = next(
        parameters for statement, parameters in cursor.calls if "rulepack_version = %s" in statement
    )
    assert completion_parameters is not None
    assert completion_parameters[0] == "분석이 완료되었지만 일부 파일에 부분 해석 경고가 있습니다."
    assert completion_parameters[2:4] == (25, RULEPACK_VERSION)
    assert completion_parameters[7:20] == (
        1,
        1,
        0,
        1,
        1,
        2,
        49,
        1,
        1,
        0,
        1,
        0,
        0,
    )
    assert [len(batch) for batch in cursor.inserted_batches] == [49, 49, 1, 1]
    inserted_issue = cursor.inserted_batches[3][0]
    assert inserted_issue[6:8] == (1, "MEDIUM")
    inserted_rationale = inserted_issue[8]
    assert isinstance(inserted_rationale, str)
    assert "kisa-2021-02-python-code-injection" in inserted_rationale
    all_sql = "\n".join(statement for statement, _parameters in cursor.calls)
    assert "ON CONFLICT" not in all_sql
    assert "archive_data = NULL" in all_sql
    assert "manifest_version = %s" in all_sql
    assert "issue_model_version = %s" in all_sql
    assert "manifest_summary_version = %s" in all_sql
    assert "issue_summary_version = %s" in all_sql
    assert "INSERT INTO scan_issues" in all_sql
    assert "detection_basis_version" in all_sql


def test_complete_scan_rejects_detection_basis_not_from_current_generator() -> None:
    finding = {
        "check_id": "kisa-2021-02-python-code-injection",
        "path": "app.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 5},
        "extra": {"message": "detected", "severity": "ERROR"},
    }
    issues = normalize_issues([finding], ["Python"])
    issues[0] = issues[0].model_copy(update={"detection_rationale": "historical rationale"})

    with pytest.raises(ValueError, match="current generator"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker-a",
            attempt=1,
            detected_languages=["Python"],
            results=normalize_results([finding], ["Python"]),
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
            issues=issues,
            manifest_nodes=[python_manifest_node(finding_count=1)],
        )


def test_complete_scan_rejects_finding_outside_target_and_bad_subtree_counts() -> None:
    semgrep_results = [
        {
            "check_id": "kisa-2021-02-python-code-injection",
            "path": "app.py",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 5},
            "extra": {"message": "detected", "severity": "ERROR"},
        }
    ]
    results = normalize_results(semgrep_results, ["Python"])

    with pytest.raises(ValueError, match="TARGET file"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker",
            attempt=1,
            detected_languages=["Python"],
            results=results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
            issues=normalize_issues(semgrep_results, ["Python"]),
            manifest_nodes=[python_manifest_node(path="other.py")],
        )

    directory = ScanFileNode(
        path="src",
        parent_path=None,
        name="src",
        depth=1,
        entry_type="DIRECTORY",
        size_bytes=None,
        language=None,
        analysis_state="DIRECTORY",
        finding_count=0,
        has_children=True,
    )
    target = ScanFileNode(
        path="src/app.py",
        parent_path="src",
        name="app.py",
        depth=2,
        entry_type="FILE",
        size_bytes=1,
        language="Python",
        analysis_state="TARGET",
        finding_count=1,
        has_children=False,
    )
    nested_semgrep_results = [{**semgrep_results[0], "path": "src/app.py"}]
    nested_results = normalize_results(nested_semgrep_results, ["Python"])
    with pytest.raises(ValueError, match="finding counts"):
        Database("postgresql://unused:unused@localhost/unused").complete_scan(
            "scan-id",
            worker_id="worker",
            attempt=1,
            detected_languages=["Python"],
            results=nested_results,
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
            issues=normalize_issues(nested_semgrep_results, ["Python"]),
            manifest_nodes=[directory, target],
        )


class CompletionBoundaryCursor:
    def __init__(
        self,
        snapshot: dict[str, object] | None,
        existing: dict[str, object] | None = None,
    ) -> None:
        self.fetchones = [snapshot]
        if snapshot is not None:
            self.fetchones.append(existing or {"has_results": False, "has_manifest": False})
        self.insert_batches = 0

    def __enter__(self) -> "CompletionBoundaryCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _statement: str, _parameters: object = None) -> None:
        return None

    def executemany(self, _statement: str, _parameters: object) -> None:
        self.insert_batches += 1

    def fetchone(self) -> dict[str, object] | None:
        return self.fetchones.pop(0)


class CompletionBoundaryConnection:
    def __init__(self, cursor: CompletionBoundaryCursor) -> None:
        self.boundary_cursor = cursor

    def __enter__(self) -> "CompletionBoundaryConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> CompletionBoundaryCursor:
        return self.boundary_cursor


def valid_completion_snapshot() -> dict[str, object]:
    return {
        "archive_file_count": 1,
        "analysis_file_count": 1,
        "detected_languages": ["Python"],
        "language_file_counts": {"Python": 1},
        "engine_name": "Semgrep",
        "engine_version": "1.174.0",
        "rulepack_name": "KISA 2021 SAST",
        "rulepack_version": PACKAGED_RULEPACK_MANIFEST.version,
        "ruleset_digest": PACKAGED_RULEPACK_MANIFEST.digest,
        "registered_rule_count": len(PACKAGED_RULEPACK_MANIFEST.rule_ids),
        "supported_rule_count": 27,
        "total_units": 1,
        "completed_units": 0,
        "archive_data": b"PK",
        "manifest_version": None,
        "manifest_node_count": None,
    }


@pytest.mark.parametrize(
    ("snapshot", "existing", "error"),
    [
        (None, None, StaleScanLeaseError),
        (
            {**valid_completion_snapshot(), "archive_file_count": 2},
            None,
            ScanSnapshotConflictError,
        ),
        (
            valid_completion_snapshot(),
            {"has_results": True, "has_manifest": False},
            ScanSnapshotConflictError,
        ),
    ],
)
def test_complete_scan_stale_conflict_and_retry_leave_no_partial_manifest(
    monkeypatch: pytest.MonkeyPatch,
    snapshot: dict[str, object] | None,
    existing: dict[str, object] | None,
    error: type[Exception],
) -> None:
    cursor = CompletionBoundaryCursor(snapshot, existing)
    database = Database("postgresql://unused:unused@localhost/unused")
    monkeypatch.setattr(
        database,
        "_connect",
        lambda: cast(Any, CompletionBoundaryConnection(cursor)),
    )

    with pytest.raises(error):
        database.complete_scan(
            "scan-id",
            worker_id="worker",
            attempt=2,
            detected_languages=["Python"],
            results=normalize_results([], ["Python"]),
            rulepack_manifest=PACKAGED_RULEPACK_MANIFEST,
            manifest_nodes=[python_manifest_node()],
        )

    assert cursor.insert_batches == 0


class ResultsCursor:
    def __init__(self, scan: dict[str, object], results: list[JsonObject]) -> None:
        self.scan = scan
        self.results = results
        self.execute_count = 0

    def __enter__(self) -> "ResultsCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _statement: str, _parameters: tuple[object, ...]) -> None:
        self.execute_count += 1

    def fetchone(self) -> dict[str, object]:
        return self.scan

    def fetchall(self) -> list[dict[str, JsonObject]]:
        return [{"result": result} for result in self.results]


class ResultsConnection:
    def __init__(self, cursor: ResultsCursor) -> None:
        self.results_cursor = cursor

    def __enter__(self) -> "ResultsConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> ResultsCursor:
        return self.results_cursor


def test_get_results_uses_stored_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = normalize_results([], ["Java"])
    cursor = ResultsCursor(
        {
            "status": "COMPLETED",
            "detected_languages": ["Java"],
            "supported_rule_count": 7,
            "rulepack_version": "archived-pack-v7",
        },
        rows,
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ResultsConnection(cursor)))

    result = database.get_results("scan-id")

    assert result is not None
    assert result.supported_rule_count == 7
    assert result.rulepack_version == "archived-pack-v7"


def test_get_results_keeps_unknown_snapshot_and_preserves_historical_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "legacy/app.py"}],
        ["Python"],
    )
    for row in rows:
        row.pop("description")
        row.pop("implementation_status")
        findings = cast(list[JsonObject], row["findings"])
        for finding in findings:
            finding.pop("kind")
    historical_finding = cast(list[JsonObject], rows[1]["findings"])[0]
    historical_finding["rule_id"] = "toy-sast-smoke-python-eval"
    historical_finding["path"] = "/legacy/work/app.py"
    cursor = ResultsCursor(
        {
            "status": "COMPLETED",
            "detected_languages": ["Python"],
            "supported_rule_count": None,
            "rulepack_version": None,
        },
        rows,
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ResultsConnection(cursor)))

    result = database.get_results("scan-id")

    assert result is not None
    assert result.supported_rule_count is None
    assert result.rulepack_version is None
    assert result.results[1].description is None
    assert result.results[1].implementation_status is None
    assert result.results[1].result_status == "DETECTED"
    assert result.results[1].finding_count == 1
    assert result.results[1].findings[0].rule_id == "toy-sast-smoke-python-eval"
    assert result.results[1].findings[0].path == "/legacy/work/app.py"
    assert result.results[1].findings[0].kind is None


def test_get_results_preserves_complete_archived_snapshot_and_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "legacy/app.py"}],
        ["Python"],
    )
    for row in rows:
        row.pop("description")
        row.pop("implementation_status")
        for finding in cast(list[JsonObject], row["findings"]):
            finding.pop("kind")
    historical_finding = cast(list[JsonObject], rows[1]["findings"])[0]
    historical_finding["rule_id"] = "toy-sast-smoke-python-eval"
    historical_finding["path"] = "/legacy/work/app.py"
    cursor = ResultsCursor(
        {
            "status": "COMPLETED",
            "detected_languages": ["Python"],
            "supported_rule_count": 7,
            "rulepack_version": "archived-pack-v7",
        },
        rows,
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ResultsConnection(cursor)))

    result = database.get_results("scan-id")

    assert result is not None
    assert result.supported_rule_count == 7
    assert result.rulepack_version == "archived-pack-v7"
    assert result.results[1].findings[0].rule_id == "toy-sast-smoke-python-eval"
    assert result.results[1].findings[0].path == "/legacy/work/app.py"


def test_get_results_preserves_each_partial_snapshot_field_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ResultsCursor(
        {
            "status": "COMPLETED",
            "detected_languages": [],
            "supported_rule_count": None,
            "rulepack_version": "archived-pack-v7",
        },
        normalize_results([], []),
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ResultsConnection(cursor)))

    result = database.get_results("scan-id")

    assert result is not None
    assert result.supported_rule_count is None
    assert result.rulepack_version == "archived-pack-v7"


def test_get_results_reads_persisted_current_rulepack_without_reapplying_write_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"}],
        ["Python"],
    )
    cast(list[JsonObject], rows[1]["findings"])[0]["path"] = "/workspace/src/app.py"
    cursor = ResultsCursor(
        {
            "status": "COMPLETED",
            "detected_languages": ["Python"],
            "supported_rule_count": 27,
            "rulepack_version": RULEPACK_VERSION,
        },
        rows,
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ResultsConnection(cursor)))

    result = database.get_results("scan-id")

    assert result is not None
    assert result.results[1].findings[0].path == "/workspace/src/app.py"


def test_get_results_rejects_out_of_order_legacy_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = normalize_results([], [])
    rows[0], rows[1] = rows[1], rows[0]
    cursor = ResultsCursor(
        {
            "status": "COMPLETED",
            "detected_languages": [],
            "supported_rule_count": 7,
            "rulepack_version": "archived-pack-v7",
        },
        rows,
    )
    database = Database("postgresql://unused:unused@localhost/unused")
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ResultsConnection(cursor)))

    with pytest.raises(ValueError, match="all 49 canonical weaknesses"):
        database.get_results("scan-id")


class ManifestCursor:
    def __init__(
        self,
        fetchones: list[dict[str, object] | None],
        rows: list[dict[str, object]] | None = None,
        result_rows: list[dict[str, object]] | None = None,
    ) -> None:
        self.fetchones = fetchones
        self.rows = rows or []
        self.result_rows = result_rows or [
            {"result": result} for result in normalize_results([], [])
        ]
        self.calls: list[tuple[str, object]] = []

    def __enter__(self) -> "ManifestCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object = None) -> None:
        self.calls.append((statement, parameters))

    def fetchone(self) -> dict[str, object] | None:
        statement, parameters = self.calls[-1]
        if "FROM scan_files AS node" in statement:
            assert isinstance(parameters, tuple)
            return next((row for row in self.rows if row["path"] == parameters[1]), None)
        row = self.fetchones.pop(0)
        if row is None or "FROM scan_runs" not in statement:
            return row
        return {key: value for key, value in row.items() if key in statement}

    def fetchall(self) -> list[dict[str, object]]:
        statement, parameters = self.calls[-1]
        if "scan_weakness_results" in statement:
            return self.result_rows
        assert isinstance(parameters, tuple)
        parent_path = parameters[1]
        rows = [row for row in self.rows if row["parent_path"] == parent_path]
        rows.sort(
            key=lambda row: (
                0 if row["node_type"] == "DIRECTORY" else 1,
                str(row["path"]).encode(),
            )
        )
        if len(parameters) == 5:
            cursor_position = (parameters[2], str(parameters[3]).encode())
            rows = [
                row
                for row in rows
                if (
                    0 if row["node_type"] == "DIRECTORY" else 1,
                    str(row["path"]).encode(),
                )
                > cursor_position
            ]
        return rows[: int(parameters[-1])]


class ManifestConnection:
    def __init__(self, cursor: ManifestCursor) -> None:
        self.manifest_cursor = cursor

    def __enter__(self) -> "ManifestConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> ManifestCursor:
        return self.manifest_cursor


def manifest_row(
    path: str,
    *,
    parent_path: str | None,
    node_type: str,
    state: str,
    has_children: bool,
) -> dict[str, object]:
    return {
        "path": path,
        "parent_path": parent_path,
        "depth": len(path.split("/")),
        "node_type": node_type,
        "size": 0 if node_type == "DIRECTORY" else 12,
        "language": "Python" if state == "TARGET" else None,
        "state": state,
        "finding_count": 0,
        "has_children": has_children,
    }


def manifest_snapshot_scan(
    *,
    node_count: int,
    root_count: int,
    directory_count: int,
    file_count: int,
    finding_count: int = 0,
) -> dict[str, object]:
    return {
        "status": "COMPLETED",
        "manifest_version": 1,
        "manifest_node_count": node_count,
        "manifest_summary_version": 1,
        "manifest_root_count": root_count,
        "manifest_directory_count": directory_count,
        "manifest_file_count": file_count,
        "manifest_finding_count": finding_count,
        "archive_file_count": file_count,
        "analysis_file_count": 1 if file_count else 0,
        "issue_model_version": None,
        "issue_summary_version": None,
        "issue_count": None,
    }


def manifest_database(monkeypatch: pytest.MonkeyPatch, cursor: ManifestCursor) -> Database:
    database = Database(
        "postgresql://unused:unused@localhost/unused",
        cursor_secret="cursor-secret",  # noqa: S106 - deterministic cursor test key
    )
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, ManifestConnection(cursor)))
    return database


def test_get_scan_files_returns_direct_children_directories_first_and_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = ManifestCursor(
        [
            manifest_snapshot_scan(node_count=3, root_count=2, directory_count=1, file_count=2),
        ],
        [
            manifest_row(
                "src",
                parent_path=None,
                node_type="DIRECTORY",
                state="DIRECTORY",
                has_children=True,
            ),
            manifest_row(
                "README.md",
                parent_path=None,
                node_type="FILE",
                state="UNSUPPORTED_EXTENSION",
                has_children=False,
            ),
            manifest_row(
                "src/app.py",
                parent_path="src",
                node_type="FILE",
                state="TARGET",
                has_children=False,
            ),
        ],
    )
    database = manifest_database(monkeypatch, cursor)

    page = database.get_scan_files("scan-id", parent_path=None, limit=1, cursor=None)

    assert page is not None
    assert page.manifest_available is True
    assert page.manifest_version == 1
    assert [node.path for node in page.items] == ["src"]
    assert page.items[0].has_children is True
    assert page.next_cursor is not None
    manifest_sql = next(sql for sql, _ in cursor.calls if "FROM scan_files AS node" in sql)
    assert "EXISTS" in manifest_sql


def test_get_scan_files_selects_every_required_current_issue_summary_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = manifest_snapshot_scan(
        node_count=39,
        root_count=1,
        directory_count=9,
        file_count=30,
        finding_count=87,
    )
    scan.update(
        {
            "issue_model_version": 1,
            "issue_summary_version": 1,
            "coverage_result_count": 49,
            "issue_count": 87,
            "detected_issue_count": 80,
            "review_signal_count": 7,
            "issue_error_count": 10,
            "issue_warning_count": 60,
            "issue_info_count": 10,
            "issue_counts_by_weakness": {"KISA-2021-02": 87},
        }
    )
    root = manifest_row(
        "src",
        parent_path=None,
        node_type="DIRECTORY",
        state="DIRECTORY",
        has_children=True,
    )
    root["finding_count"] = 87
    cursor = ManifestCursor([scan], [root])
    database = manifest_database(monkeypatch, cursor)

    page = database.get_scan_files("scan-id", parent_path=None, limit=100, cursor=None)

    assert page is not None
    scan_sql = next(sql for sql, _ in cursor.calls if "FROM scan_runs" in sql)
    assert all(
        field in scan_sql
        for field in (
            "coverage_result_count",
            "detected_issue_count",
            "review_signal_count",
            "issue_error_count",
            "issue_warning_count",
            "issue_info_count",
            "issue_counts_by_weakness",
        )
    )


def test_get_scan_files_cursor_is_signed_context_bound_and_paginates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_cursor = ManifestCursor(
        [
            manifest_snapshot_scan(node_count=3, root_count=2, directory_count=1, file_count=2),
        ],
        [
            manifest_row(
                "src",
                parent_path=None,
                node_type="DIRECTORY",
                state="DIRECTORY",
                has_children=True,
            ),
            manifest_row(
                "README.md",
                parent_path=None,
                node_type="FILE",
                state="UNSUPPORTED_EXTENSION",
                has_children=False,
            ),
            manifest_row(
                "src/app.py",
                parent_path="src",
                node_type="FILE",
                state="TARGET",
                has_children=False,
            ),
        ],
    )
    database = manifest_database(monkeypatch, first_cursor)
    first = database.get_scan_files("scan-id", parent_path=None, limit=1, cursor=None)
    assert first is not None and first.next_cursor is not None

    second_cursor = ManifestCursor(
        [
            manifest_snapshot_scan(node_count=3, root_count=2, directory_count=1, file_count=2),
        ],
        [
            manifest_row(
                "src",
                parent_path=None,
                node_type="DIRECTORY",
                state="DIRECTORY",
                has_children=True,
            ),
            manifest_row(
                "README.md",
                parent_path=None,
                node_type="FILE",
                state="UNSUPPORTED_EXTENSION",
                has_children=False,
            ),
            manifest_row(
                "src/app.py",
                parent_path="src",
                node_type="FILE",
                state="TARGET",
                has_children=False,
            ),
        ],
    )
    monkeypatch.setattr(
        database,
        "_connect",
        lambda: cast(Any, ManifestConnection(second_cursor)),
    )
    second = database.get_scan_files("scan-id", parent_path=None, limit=1, cursor=first.next_cursor)
    assert second is not None
    assert [node.path for node in second.items] == ["README.md"]
    assert second.next_cursor is None

    tampered = f"{first.next_cursor[:-1]}{'A' if first.next_cursor[-1] != 'A' else 'B'}"
    with pytest.raises(InvalidScanFilesCursorError, match="signature"):
        database.get_scan_files("scan-id", parent_path=None, limit=1, cursor=tampered)
    with pytest.raises(InvalidScanFilesCursorError, match="context"):
        database.get_scan_files("other-scan", parent_path=None, limit=1, cursor=first.next_cursor)


def test_get_scan_files_legacy_running_parent_and_corruption_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = manifest_database(
        monkeypatch,
        ManifestCursor(
            [
                {
                    "status": "COMPLETED",
                    "manifest_version": None,
                    "manifest_node_count": None,
                },
                {"node_count": 0},
            ]
        ),
    )
    unavailable = legacy.get_scan_files("legacy", parent_path=None, limit=100, cursor=None)
    assert unavailable is not None
    assert unavailable.manifest_available is False
    assert unavailable.unavailable_reason == "LEGACY_SCAN"

    running = manifest_database(
        monkeypatch,
        ManifestCursor(
            [{"status": "RUNNING", "manifest_version": None, "manifest_node_count": None}]
        ),
    )
    with pytest.raises(ScanFilesNotReadyError):
        running.get_scan_files("running", parent_path=None, limit=100, cursor=None)

    bad_parent = manifest_database(
        monkeypatch,
        ManifestCursor(
            [
                manifest_snapshot_scan(node_count=1, root_count=1, directory_count=0, file_count=1),
            ],
            [
                manifest_row(
                    "app.py",
                    parent_path=None,
                    node_type="FILE",
                    state="TARGET",
                    has_children=False,
                )
            ],
        ),
    )
    with pytest.raises(ScanFileParentNotFoundError):
        bad_parent.get_scan_files("scan", parent_path="app.py", limit=100, cursor=None)
    with pytest.raises(ScanFileParentNotFoundError):
        bad_parent.get_scan_files("scan", parent_path="src/../app.py", limit=100, cursor=None)

    corrupt = manifest_database(
        monkeypatch,
        ManifestCursor(
            [
                {
                    **manifest_snapshot_scan(
                        node_count=2,
                        root_count=1,
                        directory_count=0,
                        file_count=1,
                    ),
                    "manifest_node_count": 2,
                },
            ]
        ),
    )
    with pytest.raises(CorruptScanManifestError, match="inconsistent"):
        corrupt.get_scan_files("scan", parent_path=None, limit=100, cursor=None)


@pytest.mark.parametrize(
    "corrupt_row",
    [
        {
            "path": "/absolute.py",
            "parent_path": None,
            "depth": 1,
            "node_type": "FILE",
            "size": 1,
            "language": "Python",
            "state": "TARGET",
            "finding_count": 0,
            "has_children": False,
        },
        {
            "path": "app.py",
            "parent_path": None,
            "depth": 1,
            "node_type": "FILE",
            "size": 1,
            "language": None,
            "state": "UNSUPPORTED_EXTENSION",
            "finding_count": 0,
            "has_children": False,
        },
    ],
)
def test_get_scan_files_rejects_corrupt_path_and_classification_payloads(
    monkeypatch: pytest.MonkeyPatch, corrupt_row: dict[str, object]
) -> None:
    database = manifest_database(
        monkeypatch,
        ManifestCursor(
            [
                manifest_snapshot_scan(node_count=1, root_count=1, directory_count=0, file_count=1),
            ],
            [corrupt_row],
        ),
    )

    with pytest.raises(CorruptScanManifestError, match="payload"):
        database.get_scan_files("scan", parent_path=None, limit=100, cursor=None)


def test_get_scan_files_does_not_materialize_unrelated_manifest_nodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    later_corrupt_node = manifest_row(
        "src/app.py",
        parent_path="src",
        node_type="FILE",
        state="TARGET",
        has_children=False,
    )
    later_corrupt_node["language"] = "Java"
    database = manifest_database(
        monkeypatch,
        ManifestCursor(
            [
                manifest_snapshot_scan(node_count=3, root_count=2, directory_count=1, file_count=2),
            ],
            [
                manifest_row(
                    "src",
                    parent_path=None,
                    node_type="DIRECTORY",
                    state="DIRECTORY",
                    has_children=True,
                ),
                manifest_row(
                    "README.md",
                    parent_path=None,
                    node_type="FILE",
                    state="UNSUPPORTED_EXTENSION",
                    has_children=False,
                ),
                later_corrupt_node,
            ],
        ),
    )

    page = database.get_scan_files("scan", parent_path=None, limit=1, cursor=None)

    assert page is not None
    assert [node.path for node in page.items] == ["src"]


class IssueSnapshotCursor:
    def __init__(
        self,
        *,
        scan: dict[str, object],
        coverage_rows: list[dict[str, Any]],
        issue_rows: list[dict[str, Any]],
        page_rows: list[dict[str, Any]] | None = None,
        total: int = 0,
        path_node: dict[str, object] | None = None,
    ) -> None:
        self.scan = scan
        self.coverage_rows = coverage_rows
        self.issue_rows = issue_rows
        self.page_rows = page_rows or []
        self.total = total
        self.path_node = path_node
        self.calls: list[tuple[str, object]] = []
        self._statement = ""
        self._parameters: object = None

    def __enter__(self) -> "IssueSnapshotCursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object = None) -> None:
        self._statement = statement
        self._parameters = parameters
        self.calls.append((statement, parameters))

    def fetchone(self) -> dict[str, Any] | None:
        if "FROM scan_runs" in self._statement:
            return self.scan
        if "AS coverage_count" in self._statement:
            return {
                "coverage_count": len(self.coverage_rows),
                "issue_count": len(self.issue_rows),
            }
        if "AS count FROM scan_issues" in self._statement:
            return {"count": len(self.issue_rows)}
        if "AS issue_count FROM scan_issues" in self._statement:
            return {"issue_count": len(self.issue_rows)}
        if "WHERE scan_id = %s AND issue_id = %s" in self._statement:
            assert isinstance(self._parameters, tuple)
            return next(
                (
                    row
                    for row in self.issue_rows
                    if row["scan_id"] == self._parameters[0]
                    and row["issue_id"] == self._parameters[1]
                ),
                None,
            )
        if "FROM scan_files" in self._statement:
            return self.path_node
        if "AS total FROM scan_issues" in self._statement:
            return {"total": self.total}
        raise AssertionError(f"unexpected fetchone query: {self._statement}")

    def fetchall(self) -> list[dict[str, Any]]:
        if "SELECT result FROM scan_weakness_results" in self._statement:
            return self.coverage_rows
        if "SELECT * FROM scan_issues" in self._statement:
            raise AssertionError("issue endpoints must not materialize the full snapshot")
        if "SELECT issue.* FROM scan_issues" in self._statement:
            return self.page_rows
        raise AssertionError(f"unexpected fetchall query: {self._statement}")


class IssueSnapshotConnection:
    def __init__(self, cursor: IssueSnapshotCursor) -> None:
        self.cursor_instance = cursor

    def __enter__(self) -> "IssueSnapshotConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> IssueSnapshotCursor:
        return self.cursor_instance


class FullIssueSnapshotCursor(IssueSnapshotCursor):
    def fetchall(self) -> list[dict[str, Any]]:
        if "SELECT * FROM scan_issues" in self._statement:
            return self.issue_rows
        return super().fetchall()


def issue_snapshot_rows(
    scan_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[JsonObject] = [
        {
            "check_id": "kisa-2021-02-python-code-injection",
            "path": "src/app.py",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 5},
            "extra": {"message": "dynamic execution", "severity": "ERROR"},
        },
        {
            "check_id": "kisa-2021-05-python-os-command-injection",
            "path": "src/app/child.py",
            "start": {"line": 2, "col": 1},
            "end": {"line": 2, "col": 5},
            "extra": {
                "message": "shell execution",
                "severity": "WARNING",
                "metadata": {"cwe": "CWE-78"},
            },
        },
        {
            "check_id": "kisa-2021-33-python-login-without-rate-limit",
            "path": "src/application.py",
            "start": {"line": 3, "col": 1},
            "end": {"line": 3, "col": 5},
            "extra": {"message": "rate limit signal", "severity": "INFO"},
        },
    ]
    coverage_rows = [
        {
            "result": {
                key: value
                for key, value in result.items()
                if key not in {"findings", "finding_count"}
            }
        }
        for result in normalize_results(findings, ["Python"])
    ]
    issue_rows = []
    for issue in normalize_issues(findings, ["Python"]):
        guidance = _issue_guidance_snapshot(issue)
        issue_rows.append(
            {
                **issue.model_dump(mode="json"),
                "scan_id": scan_id,
                "issue_id": issue_id_for(scan_id, issue.fingerprint),
                "guidance_version": 1,
                "automation_limitation": guidance.automation_limitation,
                "manual_verification_checks": list(guidance.manual_verification_checks),
                "remediation": guidance.remediation,
                "safe_implementation_example": guidance.safe_implementation_example,
                "guidance_references": list(guidance.references),
            }
        )
    return coverage_rows, issue_rows


def issue_snapshot_scan(*, issue_model_version: int | None = 1) -> dict[str, object]:
    scan: dict[str, object] = {
        "status": "COMPLETED",
        "detected_languages": ["Python"],
        "issue_model_version": issue_model_version,
        "engine_name": "Semgrep",
        "engine_version": "1.174.0",
        "rulepack_name": "KISA 2021 SAST",
        "rulepack_version": RULEPACK_VERSION,
        "ruleset_digest": "a" * 64,
        "registered_rule_count": 86,
        "supported_rule_count": 27,
    }
    if issue_model_version == 1:
        scan.update(
            {
                "issue_summary_version": 1,
                "coverage_result_count": 49,
                "issue_count": 3,
                "detected_issue_count": 2,
                "review_signal_count": 1,
                "issue_error_count": 1,
                "issue_warning_count": 1,
                "issue_info_count": 0,
                "issue_counts_by_weakness": {
                    "KISA-2021-02": 1,
                    "KISA-2021-05": 1,
                    "KISA-2021-33": 1,
                },
            }
        )
    else:
        scan.update(
            {
                "issue_summary_version": None,
                "coverage_result_count": None,
                "issue_count": None,
                "detected_issue_count": None,
                "review_signal_count": None,
                "issue_error_count": None,
                "issue_warning_count": None,
                "issue_info_count": None,
                "issue_counts_by_weakness": None,
            }
        )
    return scan


def issue_snapshot_database(
    monkeypatch: pytest.MonkeyPatch, cursor: IssueSnapshotCursor
) -> Database:
    database = Database(
        "postgresql://unused:unused@localhost/unused",
        cursor_secret="cursor-secret",  # noqa: S106 - deterministic cursor test key
    )
    database._schema_ready = True
    monkeypatch.setattr(database, "_connect", lambda: cast(Any, IssueSnapshotConnection(cursor)))
    return database


def test_get_scan_issues_applies_combined_filters_and_returns_global_stats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    cursor = IssueSnapshotCursor(
        scan=issue_snapshot_scan(),
        coverage_rows=coverage_rows,
        issue_rows=issue_rows,
        page_rows=[issue_rows[0]],
        total=1,
        path_node={"node_type": "FILE"},
    )
    database = issue_snapshot_database(monkeypatch, cursor)

    page = database.get_scan_issues(
        scan_id,
        filters=IssueFilters(
            result_status="DETECTED",
            severity="ERROR",
            language="Python",
            weakness_id="KISA-2021-02",
            path="src/app.py",
            path_scope=IssuePathScope.FILE,
        ),
        limit=1,
        cursor=None,
    )

    assert page is not None
    assert page.total == 1
    assert [item.path for item in page.items] == ["src/app.py"]
    assert isinstance(page.stats, IssueStats)
    assert page.stats.total_issue_count == 3
    assert page.stats.detected_issue_count == 2
    assert page.stats.review_signal_count == 1
    assert page.stats.severity_counts.model_dump(by_alias=True) == {
        "ERROR": 1,
        "WARNING": 1,
        "INFO": 0,
    }
    page_sql = next(sql for sql, _ in cursor.calls if "SELECT issue.*" in sql)
    assert all(
        clause in page_sql
        for clause in (
            "issue.result_status = %s",
            "issue.severity = %s",
            "issue.language = %s",
            "issue.weakness_id = %s",
            "issue.path = %s",
        )
    )


def test_get_scan_issues_keeps_review_signal_severity_filterable_but_out_of_stats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    review_row = issue_rows[2]
    cursor = IssueSnapshotCursor(
        scan=issue_snapshot_scan(),
        coverage_rows=coverage_rows,
        issue_rows=issue_rows,
        page_rows=[review_row],
        total=1,
    )
    database = issue_snapshot_database(monkeypatch, cursor)

    page = database.get_scan_issues(
        scan_id,
        filters=IssueFilters(result_status="REVIEW_REQUIRED", severity="INFO"),
        limit=10,
        cursor=None,
    )

    assert page is not None
    assert len(page.items) == 1
    assert page.items[0].finding_kind == "REVIEW_SIGNAL"
    assert page.items[0].severity == "INFO"
    assert page.items[0].confidence == "LOW"
    assert isinstance(page.stats, IssueStats)
    assert page.stats.review_signal_count == 1
    assert page.stats.severity_counts.info == 0
    page_sql = next(sql for sql, _ in cursor.calls if "SELECT issue.*" in sql)
    assert "issue.result_status = %s" in page_sql
    assert "issue.severity = %s" in page_sql


def test_get_scan_issues_returns_explicitly_empty_legacy_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    legacy_coverage = [{"result": result} for result in normalize_results([], [])]
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(issue_model_version=None),
            coverage_rows=legacy_coverage,
            issue_rows=[],
        ),
    )

    page = database.get_scan_issues(scan_id, filters=IssueFilters(), limit=50, cursor=None)

    assert page is not None
    assert page.issue_model_available is False
    assert page.unavailable_reason == "LEGACY_SCAN"
    assert page.items == []
    assert page.total == 0
    assert page.next_cursor is None
    assert page.stats is None


def test_get_scan_issues_directory_filter_avoids_path_prefix_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    cursor = IssueSnapshotCursor(
        scan=issue_snapshot_scan(),
        coverage_rows=coverage_rows,
        issue_rows=issue_rows,
        page_rows=[issue_rows[1]],
        total=1,
        path_node={"node_type": "DIRECTORY"},
    )
    database = issue_snapshot_database(monkeypatch, cursor)

    page = database.get_scan_issues(
        scan_id,
        filters=IssueFilters(path="src/app", path_scope=IssuePathScope.DIRECTORY),
        limit=10,
        cursor=None,
    )

    assert page is not None
    assert [item.path for item in page.items] == ["src/app/child.py"]
    count_parameters = next(
        parameters for sql, parameters in cursor.calls if "AS total FROM scan_issues" in sql
    )
    assert count_parameters == [scan_id, "src/app/"]
    count_sql = next(sql for sql, _ in cursor.calls if "AS total FROM scan_issues" in sql)
    assert "starts_with(issue.path, %s)" in count_sql
    assert " LIKE " not in count_sql


@pytest.mark.parametrize("directory", ["src/percent%", "src/under_score", "src/app"])
def test_directory_issue_filter_treats_wildcard_characters_literally(directory: str) -> None:
    sql, parameters = _issue_filter_sql(
        "scan-id",
        IssueFilters(path=directory, path_scope=IssuePathScope.DIRECTORY),
    )

    assert sql.endswith("starts_with(issue.path, %s)")
    assert parameters == ["scan-id", f"{directory}/"]


def test_get_scan_issues_cursor_is_hmac_bound_to_filter_and_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
            page_rows=issue_rows[:2],
            total=3,
        ),
    )
    first = database.get_scan_issues(scan_id, filters=IssueFilters(), limit=1, cursor=None)

    assert first is not None and first.next_cursor is not None
    assert first.items[0].path == "src/app.py"
    with pytest.raises(InvalidIssuesCursorError, match="signature"):
        database.get_scan_issues(
            scan_id,
            filters=IssueFilters(),
            limit=1,
            cursor=(f"{first.next_cursor[:-1]}{'A' if first.next_cursor[-1] != 'A' else 'B'}"),
        )
    with pytest.raises(InvalidIssuesCursorError, match="context"):
        database.get_scan_issues(
            "5ac23ca1-2434-40e3-9c3e-c0c598571cb8",
            filters=IssueFilters(),
            limit=1,
            cursor=first.next_cursor,
        )
    with pytest.raises(InvalidIssuesCursorError, match="context"):
        database.get_scan_issues(
            scan_id,
            filters=IssueFilters(severity="ERROR"),
            limit=1,
            cursor=first.next_cursor,
        )


def test_get_scan_issue_reads_only_the_requested_immutable_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    requested_issue_id = str(issue_rows[0]["issue_id"])
    corrupted_coverage = [*coverage_rows]
    corrupted_coverage[-1] = {"result": {"weakness_id": "KISA-2021-49"}}
    corrupted_issue_rows = [*issue_rows]
    corrupted_issue_rows[-1] = {**corrupted_issue_rows[-1], "message": None}

    cursor = IssueSnapshotCursor(
        scan=issue_snapshot_scan(),
        coverage_rows=corrupted_coverage,
        issue_rows=corrupted_issue_rows,
    )
    database = issue_snapshot_database(monkeypatch, cursor)

    detail = database.get_scan_issue(scan_id, requested_issue_id)

    assert detail is not None
    assert detail.issue_id == requested_issue_id
    assert not any(
        "scan_weakness_results" in sql or "ORDER BY weakness_number" in sql
        for sql, _ in cursor.calls
    )


def test_issue_detail_returns_distinct_source_free_guidance_and_official_cwe_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)

    detected_database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
        ),
    )
    detected = detected_database.get_scan_issue(scan_id, str(issue_rows[1]["issue_id"]))
    review_database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
        ),
    )
    review = review_database.get_scan_issue(scan_id, str(issue_rows[2]["issue_id"]))

    assert detected is not None and review is not None
    assert detected.detection_basis_version == 1
    assert detected.confidence == "MEDIUM"
    assert detected.rule.rule_id in detected.detection_rationale
    assert review.detection_basis_version == 1
    assert review.confidence == "LOW"
    assert "수동 검토 신호" in review.detection_rationale
    assert detected.automation_limitation != review.automation_limitation
    assert "자동으로 확인하지 않습니다" in detected.automation_limitation
    assert "자동 판정하지 않습니다" in review.automation_limitation
    assert detected.references == ["https://cwe.mitre.org/data/definitions/78.html"]
    assert review.references == ["https://cwe.mitre.org/data/index.html"]
    assert detected.evidence.reason == "SOURCE_NOT_RETAINED"
    assert "원본 코드 아님" in detected.safe_implementation_example


def test_v1_readers_use_persisted_snapshots_not_current_catalog_rule_or_generators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    coverage_rows[1]["result"]["name"] = "Historical code injection"
    issue_rows[0]["weakness_name"] = "Historical code injection"
    issue_rows[0]["detection_rationale"] = "Historical persisted detection rationale"
    issue_rows[0]["automation_limitation"] = "Historical persisted automation limit"
    monkeypatch.setattr(database_module, "CATALOG_BY_ID", {})
    monkeypatch.setattr(database_module, "RULE_REGISTRY", {})
    monkeypatch.setattr(
        database_module,
        "DETECTED_AUTOMATION_LIMITATION",
        "A future generator value",
    )
    monkeypatch.setattr(database_module, "ISSUE_GUIDANCE_VERSION", 2)
    monkeypatch.setattr(database_module, "SNAPSHOT_SUMMARY_VERSION", 2)
    monkeypatch.setattr(database_module, "CWE_INDEX_URL", "https://future.invalid/cwe")
    monkeypatch.setattr(
        database_module,
        "_current_issue_guidance_references",
        lambda _issue: ("https://future.invalid/generated-reference",),
    )
    current_guidance = _issue_guidance_snapshot(
        database_module._validate_stored_issues([issue_rows[0]])[0]
    )
    assert current_guidance.references == ("https://future.invalid/generated-reference",)

    results_database = issue_snapshot_database(
        monkeypatch,
        FullIssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
        ),
    )
    results = results_database.get_results(scan_id)
    assert results is not None
    assert results.results[1].name == "Historical code injection"

    list_database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
            page_rows=[issue_rows[0]],
            total=1,
        ),
    )
    page = list_database.get_scan_issues(scan_id, filters=IssueFilters(), limit=10, cursor=None)
    assert page is not None
    assert page.items[0].weakness_name == "Historical code injection"
    assert page.items[0].detection_rationale == "Historical persisted detection rationale"

    detail_database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
        ),
    )
    detail = detail_database.get_scan_issue(scan_id, str(issue_rows[0]["issue_id"]))
    assert detail is not None
    assert detail.weakness.name == "Historical code injection"
    assert detail.automation_limitation == "Historical persisted automation limit"
    assert detail.detection_rationale == "Historical persisted detection rationale"
    assert detail.references == ["https://cwe.mitre.org/data/index.html"]

    cwe_detail_database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
        ),
    )
    cwe_detail = cwe_detail_database.get_scan_issue(scan_id, str(issue_rows[1]["issue_id"]))
    assert cwe_detail is not None
    assert cwe_detail.references == ["https://cwe.mitre.org/data/definitions/78.html"]

    coverage_database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
        ),
    )
    coverage = coverage_database.get_scan_coverage(scan_id)
    assert coverage is not None
    assert coverage.items[1].name == "Historical code injection"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("guidance_version", 2),
        ("automation_limitation", ""),
        ("guidance_references", ["https://example.invalid/reference"]),
        ("guidance_references", ["http://example.invalid"]),
    ],
)
def test_issue_detail_fails_closed_on_corrupt_guidance_snapshot(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    corrupt_rows = [*issue_rows]
    corrupt_rows[0] = {
        **corrupt_rows[0],
        field: value,
    }
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=corrupt_rows,
        ),
    )

    with pytest.raises(CorruptScanIssueModelError, match="detail payload"):
        database.get_scan_issue(scan_id, str(corrupt_rows[0]["issue_id"]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("detection_basis_version", 2),
        ("confidence", "HIGH"),
        ("detection_rationale", ""),
    ],
)
def test_issue_detail_fails_closed_on_corrupt_detection_snapshot(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    corrupt_rows = [*issue_rows]
    corrupt_rows[0] = {**corrupt_rows[0], field: value}
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(),
            coverage_rows=coverage_rows,
            issue_rows=corrupt_rows,
        ),
    )

    with pytest.raises(CorruptScanIssueModelError, match="detail payload"):
        database.get_scan_issue(scan_id, str(corrupt_rows[0]["issue_id"]))


def test_get_scan_issues_pages_without_materializing_the_issue_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    corrupted_issue_rows = [*issue_rows]
    corrupted_issue_rows[-1] = {**corrupted_issue_rows[-1], "message": None}
    cursor = IssueSnapshotCursor(
        scan=issue_snapshot_scan(),
        coverage_rows=coverage_rows,
        issue_rows=corrupted_issue_rows,
        page_rows=[issue_rows[0]],
        total=3,
    )
    database = issue_snapshot_database(monkeypatch, cursor)

    page = database.get_scan_issues(scan_id, filters=IssueFilters(), limit=1, cursor=None)

    assert page is not None
    assert [item.issue_id for item in page.items] == [issue_rows[0]["issue_id"]]
    assert not any(
        "SELECT * FROM scan_issues" in sql or "SELECT result FROM scan_weakness_results" in sql
        for sql, _ in cursor.calls
    )


@pytest.mark.parametrize("operation", ["list", "detail", "coverage"])
def test_issue_endpoints_fail_closed_on_corrupt_completion_summary(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    corrupt_scan = issue_snapshot_scan()
    corrupt_scan["issue_count"] = 4
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=corrupt_scan,
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
            page_rows=[issue_rows[0]],
            total=3,
        ),
    )

    with pytest.raises(CorruptScanIssueModelError, match="summary"):
        if operation == "list":
            database.get_scan_issues(scan_id, filters=IssueFilters(), limit=1, cursor=None)
        elif operation == "detail":
            database.get_scan_issue(scan_id, str(issue_rows[0]["issue_id"]))
        else:
            database.get_scan_coverage(scan_id)


@pytest.mark.parametrize("operation", ["results", "list", "detail", "coverage"])
def test_issue_readers_fail_closed_on_unsupported_declared_model_version(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    cursor_type = FullIssueSnapshotCursor if operation == "results" else IssueSnapshotCursor
    database = issue_snapshot_database(
        monkeypatch,
        cursor_type(
            scan=issue_snapshot_scan(issue_model_version=3),
            coverage_rows=coverage_rows,
            issue_rows=issue_rows,
            page_rows=[issue_rows[0]],
            total=3,
        ),
    )

    with pytest.raises(CorruptScanIssueModelError, match="unsupported issue model version"):
        if operation == "results":
            database.get_results(scan_id)
        elif operation == "list":
            database.get_scan_issues(scan_id, filters=IssueFilters(), limit=1, cursor=None)
        elif operation == "detail":
            database.get_scan_issue(scan_id, str(issue_rows[0]["issue_id"]))
        else:
            database.get_scan_coverage(scan_id)


def test_get_scan_issue_rejects_cross_scan_and_unknown_issue_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(), coverage_rows=coverage_rows, issue_rows=issue_rows
        ),
    )

    assert database.get_scan_issue(scan_id, "00000000-0000-0000-0000-000000000000") is None
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(), coverage_rows=coverage_rows, issue_rows=issue_rows
        ),
    )
    assert (
        database.get_scan_issue(
            scan_id, issue_id_for("5ac23ca1-2434-40e3-9c3e-c0c598571cb8", "a" * 64)
        )
        is None
    )


def test_get_scan_coverage_returns_exact_v1_and_legacy_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    coverage_rows, issue_rows = issue_snapshot_rows(scan_id)
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(), coverage_rows=coverage_rows, issue_rows=issue_rows
        ),
    )
    current = database.get_scan_coverage(scan_id)
    assert current is not None
    assert current.coverage_model_version == 1
    assert len(current.items) == 49
    assert current.summary.total_finding_count == 3

    legacy_coverage = [{"result": result} for result in normalize_results([], [])]
    database = issue_snapshot_database(
        monkeypatch,
        IssueSnapshotCursor(
            scan=issue_snapshot_scan(issue_model_version=None),
            coverage_rows=legacy_coverage,
            issue_rows=[],
        ),
    )
    legacy = database.get_scan_coverage(scan_id)
    assert legacy is not None
    assert legacy.coverage_model_version is None
    assert len(legacy.items) == 49
