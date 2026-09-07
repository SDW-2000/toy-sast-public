import logging
import shutil
from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from typing import cast
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from app.config import Settings
from app.database import Database, ScanSnapshotConflictError, StaleScanLeaseError
from app.engine import ENGINE_VERSION, EngineIntegrityError
from app.rule_registry import RulepackManifest
from app.schemas import ClaimedScan, JsonObject, NormalizedIssue, ScanFileNode
from app.worker import (
    _completion_message,
    _workspace_for_scan,
    process_scan,
    reap_terminal_workspace_roots,
)

PACKAGED_RULES_ROOT = Path(__file__).resolve().parents[2] / "analyzer" / "rules"


@pytest.fixture(autouse=True)
def use_pinned_engine_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep worker unit tests independent from the optional analyzer dependency."""
    monkeypatch.setattr("app.worker.validate_engine_version", lambda: ENGINE_VERSION)


class RecordingDatabase:
    def __init__(self) -> None:
        self.progress: list[tuple[int, int]] = []
        self.progress_events: list[tuple[str, int, int, str]] = []
        self.completed_results: list[JsonObject] | None = None
        self.completed_issues: list[NormalizedIssue] | None = None
        self.completed_languages: list[str] | None = None
        self.failure: tuple[str, str] | None = None
        self.engine_snapshot: dict[str, object] | None = None
        self.target_metadata: dict[str, object] | None = None
        self.manifest_nodes: list[ScanFileNode] | None = None
        self.completion_message: str | None = None
        self.reapable_scan_ids: set[str] = set()
        self.lease_renewals: list[tuple[str, str, int]] = []

    def record_engine_snapshot(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        engine_name: str,
        engine_version: str,
        rulepack_name: str,
        rulepack_manifest: RulepackManifest,
    ) -> None:
        self.engine_snapshot = {
            "engine_name": engine_name,
            "engine_version": engine_version,
            "rulepack_name": rulepack_name,
            "rulepack_version": rulepack_manifest.version,
            "digest": rulepack_manifest.digest,
        }

    def record_target_metadata(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        archive_file_count: int,
        analysis_file_count: int,
        detected_languages: Sequence[str],
        language_file_counts: dict[str, int],
        executed_rule_count: int,
    ) -> None:
        self.target_metadata = {
            "archive_file_count": archive_file_count,
            "analysis_file_count": analysis_file_count,
            "detected_languages": list(detected_languages),
            "language_file_counts": language_file_counts,
            "executed_rule_count": executed_rule_count,
        }

    def update_progress(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        phase: str,
        completed_units: int,
        total_units: int,
        message: str,
        detected_languages: Sequence[str] | None = None,
    ) -> None:
        self.progress.append((completed_units, total_units))
        self.progress_events.append((phase, completed_units, total_units, message))

    def renew_scan_lease(self, scan_id: str, *, worker_id: str, attempt: int) -> None:
        self.lease_renewals.append((scan_id, worker_id, attempt))

    def complete_scan(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        detected_languages: Sequence[str],
        results: Sequence[JsonObject],
        rulepack_manifest: RulepackManifest,
        issues: Sequence[NormalizedIssue],
        manifest_nodes: Sequence[ScanFileNode],
        completion_message: str = "분석이 완료되었습니다.",
    ) -> None:
        self.completed_languages = list(detected_languages)
        self.completed_results = list(results)
        self.completed_issues = list(issues)
        self.manifest_nodes = list(manifest_nodes)
        self.completion_message = completion_message

    def fail_scan(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        error_code: str,
        message: str,
    ) -> None:
        self.failure = (error_code, message)

    def is_scan_workspace_reapable(self, scan_id: str) -> bool:
        return scan_id in self.reapable_scan_ids

    def clear_deleted_scan_workspace(self, scan_id: str) -> None:
        self.reapable_scan_ids.discard(scan_id)

    def list_deleted_scan_workspaces(self) -> list[str]:
        return list(self.reapable_scan_ids)


def make_zip(extra_entries: dict[str, str] | None = None, *, include_default: bool = True) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        if include_default:
            archive.writestr("src/app.py", "value = eval(user_input)")
        for path, content in (extra_entries or {}).items():
            archive.writestr(path, content)
    return output.getvalue()


def test_terminal_workspace_janitor_reaps_completed_and_exhausted_failure(
    tmp_path: Path,
) -> None:
    database = RecordingDatabase()
    completed_id = "11111111-1111-1111-1111-111111111111"
    exhausted_id = "22222222-2222-2222-2222-222222222222"
    database.reapable_scan_ids = {completed_id, exhausted_id}
    for scan_id in database.reapable_scan_ids:
        attempt = tmp_path / scan_id / "attempt-3-crashed-worker"
        attempt.mkdir(parents=True)
        (attempt / "source.py").write_text("secret = 'stale'", encoding="utf-8")

    reap_terminal_workspace_roots(cast(Database, database), tmp_path)

    assert not (tmp_path / completed_id).exists()
    assert not (tmp_path / exhausted_id).exists()
    assert database.reapable_scan_ids == set()


def test_terminal_workspace_janitor_clears_tombstone_when_workspace_is_absent(
    tmp_path: Path,
) -> None:
    database = RecordingDatabase()
    scan_id = "77777777-7777-7777-7777-777777777777"
    database.reapable_scan_ids = {scan_id}

    reap_terminal_workspace_roots(cast(Database, database), tmp_path)

    assert database.reapable_scan_ids == set()


def test_terminal_workspace_janitor_refuses_active_unknown_invalid_and_symlinked_paths(
    tmp_path: Path,
) -> None:
    database = RecordingDatabase()
    active_id = "33333333-3333-3333-3333-333333333333"
    unknown_id = "44444444-4444-4444-4444-444444444444"
    active_root = tmp_path / active_id
    unknown_root = tmp_path / unknown_id
    invalid_root = tmp_path / "not-a-scan-id"
    for root in (active_root, unknown_root, invalid_root):
        (root / "attempt-1-worker").mkdir(parents=True)
    target = tmp_path / "symlink-target"
    target.mkdir()
    symlink_root = tmp_path / "55555555-5555-5555-5555-555555555555"
    symlink_root.symlink_to(target, target_is_directory=True)

    reap_terminal_workspace_roots(cast(Database, database), tmp_path)

    assert active_root.exists()
    assert unknown_root.exists()
    assert invalid_root.exists()
    assert symlink_root.is_symlink()
    assert target.exists()


def test_terminal_workspace_janitor_logs_cleanup_failure_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    database = RecordingDatabase()
    scan_id = "66666666-6666-6666-6666-666666666666"
    database.reapable_scan_ids = {scan_id}
    workspace = tmp_path / scan_id
    (workspace / "attempt-3-crashed-worker").mkdir(parents=True)
    real_rmtree = shutil.rmtree
    calls = 0

    def fail_once(path: str | Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("workspace locked")
        real_rmtree(path)

    monkeypatch.setattr("app.worker.shutil.rmtree", fail_once)

    with caplog.at_level(logging.ERROR, logger="app.worker"):
        reap_terminal_workspace_roots(cast(Database, database), tmp_path)
        assert workspace.exists()
        reap_terminal_workspace_roots(cast(Database, database), tmp_path)

    assert calls == 2
    assert not workspace.exists()
    assert "terminal workspace cleanup failed" in caplog.text


def test_stale_worker_attempt_never_removes_sibling_retry_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    monkeypatch.setattr("app.worker.run_semgrep", lambda *_args, **_kwargs: [])
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-001",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )
    stale_workspace = _workspace_for_scan(tmp_path, scan)
    stale_workspace.mkdir(parents=True)
    (stale_workspace / "stale.py").write_text("stale", encoding="utf-8")
    other_attempt_workspace = tmp_path / "scan-001" / "attempt-2-other-worker"
    other_attempt_workspace.mkdir(parents=True)
    (other_attempt_workspace / "active.py").write_text("active", encoding="utf-8")

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.completed_results is not None
    assert len(database.completed_results) == 49
    assert database.progress == sorted(database.progress)
    assert {total for _, total in database.progress} == {53}
    assert database.progress[-1] == (52, 53)
    analysis_events = [event for event in database.progress_events if event[0] == "ANALYZING"]
    assert analysis_events == [
        ("ANALYZING", 2, 53, "등록된 SAST 보안 규칙을 실행하고 있습니다."),
        ("ANALYZING", 3, 53, "등록된 SAST 보안 규칙 실행을 완료했습니다."),
    ]
    assert database.engine_snapshot is not None
    assert database.engine_snapshot["engine_version"] == "1.174.0"
    assert database.target_metadata == {
        "archive_file_count": 1,
        "analysis_file_count": 1,
        "detected_languages": ["Python"],
        "language_file_counts": {"Python": 1},
        "executed_rule_count": 25,
    }
    assert database.manifest_nodes is not None
    assert {node.path for node in database.manifest_nodes} == {"src", "src/app.py"}
    assert not stale_workspace.exists()
    assert (other_attempt_workspace / "active.py").read_text(encoding="utf-8") == "active"


def test_worker_connects_analyzer_heartbeat_to_scan_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()

    def analyze_with_heartbeat(*args: object, **_kwargs: object) -> list[JsonObject]:
        heartbeat = args[-1]
        assert callable(heartbeat)
        heartbeat()
        return []

    monkeypatch.setattr("app.worker.run_semgrep", analyze_with_heartbeat)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-heartbeat",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.lease_renewals == [("scan-heartbeat", "worker-001", 1)]
    assert database.completed_results is not None


def test_worker_discards_results_when_analyzer_heartbeat_loses_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()

    def lose_lease(*_args: object, **_kwargs: object) -> None:
        raise StaleScanLeaseError("lease lost")

    def analyze_until_lease_loss(*args: object, **_kwargs: object) -> list[JsonObject]:
        heartbeat = args[-1]
        assert callable(heartbeat)
        heartbeat()
        pytest.fail("analysis must stop as soon as the heartbeat loses its lease")

    monkeypatch.setattr(database, "renew_scan_lease", lose_lease)
    monkeypatch.setattr("app.worker.run_semgrep", analyze_until_lease_loss)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-heartbeat-lease-loss",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.completed_results is None
    assert database.failure is None
    assert not _workspace_for_scan(tmp_path, scan).exists()


def test_worker_completes_with_partial_parsing_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()

    def analyze_with_partial_parsing(*_args: object, **kwargs: object) -> list[JsonObject]:
        reporter = kwargs["partial_parsing_reporter"]
        assert callable(reporter)
        reporter(("src/broken.py", "legacy/nashorn.js"))
        return []

    monkeypatch.setattr("app.worker.run_semgrep", analyze_with_partial_parsing)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-partial-parsing",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.completed_results is not None
    assert database.completion_message is not None
    assert "완전히 해석하지 못했습니다(2개)" in database.completion_message
    assert "src/broken.py" in database.completion_message
    assert "legacy/nashorn.js" in database.completion_message


def test_partial_parsing_completion_message_bounds_long_paths() -> None:
    message = _completion_message([f"src/{'nested/' * 700}broken.py"])

    assert len(message) < 4000
    assert message.endswith("broken.py")


def test_worker_removes_extracted_source_before_committing_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    monkeypatch.setattr("app.worker.run_semgrep", lambda *_args, **_kwargs: [])
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-clean-before-complete",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )
    workspace = _workspace_for_scan(tmp_path, scan)
    complete_scan = database.complete_scan

    def assert_workspace_removed(
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        detected_languages: Sequence[str],
        results: Sequence[JsonObject],
        rulepack_manifest: RulepackManifest,
        issues: Sequence[NormalizedIssue],
        manifest_nodes: Sequence[ScanFileNode],
        completion_message: str = "분석이 완료되었습니다.",
    ) -> None:
        assert not workspace.exists()
        complete_scan(
            scan_id,
            worker_id=worker_id,
            attempt=attempt,
            detected_languages=detected_languages,
            results=results,
            rulepack_manifest=rulepack_manifest,
            issues=issues,
            manifest_nodes=manifest_nodes,
            completion_message=completion_message,
        )

    monkeypatch.setattr(database, "complete_scan", assert_workspace_removed)

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.completed_results is not None


def test_worker_fails_before_analysis_when_stale_attempt_workspace_cannot_be_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-stale-cleanup-failure",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=2,
    )
    workspace = _workspace_for_scan(tmp_path, scan)
    scan_root = workspace.parent
    stale_workspace = scan_root / "attempt-1-crashed-worker"
    stale_workspace.mkdir(parents=True)
    (stale_workspace / "stale.py").write_text("stale", encoding="utf-8")
    analyzer_called = False

    def fail_workspace_removal(path: str | Path, *_args: object, **_kwargs: object) -> None:
        if Path(path) == scan_root:
            raise OSError("workspace is locked")
        if Path(path) == workspace:
            raise FileNotFoundError(path)
        raise AssertionError(f"unexpected deletion target: {path}")

    def unexpected_analysis(*_args: object, **_kwargs: object) -> list[JsonObject]:
        nonlocal analyzer_called
        analyzer_called = True
        return []

    monkeypatch.setattr("app.worker.shutil.rmtree", fail_workspace_removal)
    monkeypatch.setattr("app.worker.run_semgrep", unexpected_analysis)

    process_scan(cast(Database, database), scan, settings)

    assert analyzer_called is False
    assert database.completed_results is None
    assert database.failure == (
        "WORKSPACE_CLEANUP_FAILED",
        "분석 작업공간을 안전하게 정리하지 못했습니다. 분석을 완료하지 않았습니다.",
    )
    assert (stale_workspace / "stale.py").exists()


def test_retry_removes_crashed_sibling_attempt_before_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-retry-removes-crashed-sibling",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-002",
        attempts=2,
    )
    workspace = _workspace_for_scan(tmp_path, scan)
    crashed_workspace = workspace.parent / "attempt-1-crashed-worker"
    crashed_workspace.mkdir(parents=True)
    (crashed_workspace / "source.py").write_text("secret = 'stale'", encoding="utf-8")

    def assert_crashed_sibling_was_removed(
        active_workspace: Path, *_args: object, **_kwargs: object
    ) -> list[JsonObject]:
        assert active_workspace == workspace
        assert not crashed_workspace.exists()
        return []

    monkeypatch.setattr("app.worker.run_semgrep", assert_crashed_sibling_was_removed)

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.completed_results is not None
    assert not workspace.parent.exists()


def test_invalid_scan_workspace_root_fails_without_cleanup_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="../outside-workspace",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=2,
    )
    deletion_targets: list[Path] = []

    def record_removal(path: str | Path, *_args: object, **_kwargs: object) -> None:
        deletion_targets.append(Path(path))

    monkeypatch.setattr("app.worker.shutil.rmtree", record_removal)

    process_scan(cast(Database, database), scan, settings)

    assert database.failure == (
        "WORKSPACE_CLEANUP_FAILED",
        "분석 작업공간을 안전하게 정리하지 못했습니다. 분석을 완료하지 않았습니다.",
    )
    assert deletion_targets == []


def test_worker_logs_final_cleanup_failure_without_committing_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    database = RecordingDatabase()
    monkeypatch.setattr("app.worker.run_semgrep", lambda *_args, **_kwargs: [])
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-final-cleanup-failure",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )
    workspace = _workspace_for_scan(tmp_path, scan)

    def fail_only_extracted_workspace(path: str | Path) -> None:
        if Path(path) == workspace and workspace.exists():
            raise OSError("workspace is locked")
        raise FileNotFoundError(path)

    monkeypatch.setattr("app.worker.shutil.rmtree", fail_only_extracted_workspace)

    with caplog.at_level(logging.ERROR, logger="app.worker"):
        process_scan(cast(Database, database), scan, settings)

    assert database.completed_results is None
    assert database.failure == (
        "WORKSPACE_CLEANUP_FAILED",
        "분석 작업공간을 안전하게 정리하지 못했습니다. 분석을 완료하지 않았습니다.",
    )
    assert "workspace cleanup failed" in caplog.text
    assert "final workspace cleanup failed" in caplog.text


def test_worker_discards_output_after_losing_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()

    def lose_lease(*_args: object, **_kwargs: object) -> None:
        raise StaleScanLeaseError("lost")

    monkeypatch.setattr(database, "update_progress", lose_lease)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-stale",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-a",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.completed_results is None
    assert database.failure is None
    assert not _workspace_for_scan(tmp_path, scan).exists()
    assert not (tmp_path / scan.scan_id).exists()


def test_worker_excludes_generated_vendor_trees_from_language_and_analysis_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    observed_targets: set[str] = set()

    def record_targets(workspace: Path, *_args: object, **_kwargs: object) -> list[JsonObject]:
        observed_targets.update(
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file() and "node_modules" not in path.parts and "dist" not in path.parts
        )
        return []

    monkeypatch.setattr("app.worker.run_semgrep", record_targets)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-exclusions",
        project_id="project-001",
        archive_data=make_zip(
            {
                "node_modules/dependency/broken.js": "function broken( { eval(input)",
                "dist/generated.py": "eval(user_input)\n",
            }
        ),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.completed_languages == ["Python"]
    assert observed_targets == {"src/app.py"}
    assert database.target_metadata is not None
    assert database.target_metadata["archive_file_count"] == 3
    assert database.target_metadata["analysis_file_count"] == 1
    assert database.manifest_nodes is not None
    manifest_by_path = {node.path: node for node in database.manifest_nodes}
    assert manifest_by_path["src/app.py"].analysis_state == "TARGET"
    assert manifest_by_path["node_modules/dependency/broken.js"].analysis_state == (
        "EXCLUDED_DIRECTORY"
    )
    assert manifest_by_path["dist/generated.py"].analysis_state == "EXCLUDED_DIRECTORY"


def test_worker_records_mixed_language_target_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    monkeypatch.setattr("app.worker.run_semgrep", lambda *_args, **_kwargs: [])
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-mixed",
        project_id="project-001",
        archive_data=make_zip(
            {
                "src/Main.java": "class Main {}",
                "src/ui.tsx": "export const UI = () => null",
                "src/worker.js": "export const run = () => 1",
                "vendor/ignored.java": "class Ignored {}",
            }
        ),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.completed_languages == ["Java", "JavaScript", "Python"]
    assert database.target_metadata is not None
    assert database.target_metadata["archive_file_count"] == 5
    assert database.target_metadata["analysis_file_count"] == 4
    assert database.target_metadata["language_file_counts"] == {
        "Java": 1,
        "JavaScript": 2,
        "Python": 1,
    }
    assert database.target_metadata["executed_rule_count"] == 79


def test_worker_completes_archive_with_only_unsupported_and_excluded_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    analyzer_calls = 0

    def record_empty_analysis(*_args: object, **_kwargs: object) -> list[JsonObject]:
        nonlocal analyzer_calls
        analyzer_calls += 1
        return []

    monkeypatch.setattr("app.worker.run_semgrep", record_empty_analysis)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-no-targets",
        project_id="project-001",
        archive_data=make_zip(
            {
                "README.txt": "plain notes",
                "vendor/generated.py": "eval(user_input)",
            },
            include_default=False,
        ),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert analyzer_calls == 0
    assert database.failure is None
    assert database.completed_languages == []
    assert database.completed_results is not None
    assert len(database.completed_results) == 49
    assert database.target_metadata == {
        "archive_file_count": 2,
        "analysis_file_count": 0,
        "detected_languages": [],
        "language_file_counts": {},
        "executed_rule_count": 0,
    }
    assert database.manifest_nodes is not None
    by_path = {node.path: node for node in database.manifest_nodes}
    assert by_path["README.txt"].analysis_state == "UNSUPPORTED_EXTENSION"
    assert by_path["vendor/generated.py"].analysis_state == "EXCLUDED_DIRECTORY"
    assert by_path["README.txt"].finding_count == 0
    assert by_path["vendor/generated.py"].finding_count == 0
    assert not (tmp_path / scan.scan_id).exists()


def test_worker_attaches_file_and_directory_finding_counts_without_source_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    monkeypatch.setattr(
        "app.worker.run_semgrep",
        lambda *_args, **_kwargs: [
            {
                "check_id": "kisa-2021-02-python-code-injection",
                "path": "src/app.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 5},
                "extra": {"message": "detected", "severity": "ERROR"},
            }
        ],
    )
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-counts",
        project_id="project-001",
        archive_data=make_zip({"notes.txt": "secret source body"}),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.failure is None
    assert database.manifest_nodes is not None
    by_path = {node.path: node for node in database.manifest_nodes}
    assert by_path["src/app.py"].finding_count == 1
    assert by_path["src"].finding_count == 1
    assert by_path["notes.txt"].analysis_state == "UNSUPPORTED_EXTENSION"
    assert "secret source body" not in str(
        [node.model_dump(mode="json") for node in database.manifest_nodes]
    )
    assert database.completed_issues is not None
    assert len(database.completed_issues) == 1
    assert database.completed_issues[0].result_status == "DETECTED"
    assert "secret source body" not in str(
        [issue.model_dump(mode="json") for issue in database.completed_issues]
    )
    assert not _workspace_for_scan(tmp_path, scan).exists()


def test_worker_fails_closed_when_engine_version_is_not_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()
    monkeypatch.setattr(
        "app.worker.validate_engine_version",
        lambda: (_ for _ in ()).throw(EngineIntegrityError("version mismatch")),
    )
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-version",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=1,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.failure == ("ANALYZER_ERROR", "version mismatch")
    assert database.completed_results is None


def test_worker_fails_closed_when_retry_snapshot_conflicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = RecordingDatabase()

    def conflict(*_args: object, **_kwargs: object) -> None:
        raise ScanSnapshotConflictError("snapshot mismatch")

    monkeypatch.setattr(database, "record_engine_snapshot", conflict)
    settings = Settings(
        database_url="postgresql://unused:unused@localhost/unused",
        session_secret="test-only-secret",  # noqa: S106
        workspace_root=str(tmp_path),
        analyzer_rules_root=str(PACKAGED_RULES_ROOT),
    )
    scan = ClaimedScan(
        scan_id="scan-retry",
        project_id="project-001",
        archive_data=make_zip(),
        worker_id="worker-001",
        attempts=2,
    )

    process_scan(cast(Database, database), scan, settings)

    assert database.failure == ("ANALYZER_STATE_CONFLICT", "snapshot mismatch")
    assert database.completed_results is None
