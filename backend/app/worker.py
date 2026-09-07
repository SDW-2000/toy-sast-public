import hashlib
import logging
import os
import shutil
import socket
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from psycopg import connect

from app.analyzer import (
    AnalyzerError,
    discover_analysis_targets,
    normalize_issues,
    normalize_results,
    run_semgrep,
    supported_rule_count,
)
from app.archive import UnsafeArchiveError, extract_archive, inspect_archive
from app.config import Settings, get_settings
from app.database import Database, ScanSnapshotConflictError, StaleScanLeaseError
from app.engine import (
    ENGINE_NAME,
    RULEPACK_NAME,
    EngineIntegrityError,
    validate_engine_version,
)
from app.file_manifest import (
    attach_issue_counts,
    build_scan_file_manifest,
    validate_scan_file_manifest,
)
from app.rule_registry import RulepackIntegrityError, validate_rulepack_manifest
from app.schemas import ClaimedScan, ScanFileState

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_WORKSPACE_CLEANUP_ERROR_CODE = "WORKSPACE_CLEANUP_FAILED"
_WORKSPACE_CLEANUP_MESSAGE = (
    "분석 작업공간을 안전하게 정리하지 못했습니다. 분석을 완료하지 않았습니다."
)
_WORKSPACE_JANITOR_INTERVAL_SECONDS = 30.0


class WorkspaceCleanupError(RuntimeError):
    """Raised when a deterministic extracted-source workspace cannot be removed."""


def wait_for_database(database_url: str) -> None:
    while True:
        try:
            with connect(database_url, connect_timeout=2) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            return
        except Exception:
            logger.info("waiting for PostgreSQL")
            time.sleep(2)


def process_scan(database: Database, scan: ClaimedScan, settings: Settings) -> None:
    workspace_root = Path(settings.workspace_root)
    workspace = _workspace_for_scan(workspace_root, scan)
    scan_workspace_root: Path | None = None
    # Every claim attempt owns a separate directory. A late worker must never delete or
    # mutate the active retry's workspace after its database lease has been fenced out.
    try:
        scan_workspace_root = _scan_workspace_root(workspace_root, scan, workspace)
        _prepare_attempt_workspace(scan, workspace, scan_workspace_root)
        engine_version = validate_engine_version()
        rulepack_manifest = validate_rulepack_manifest(Path(settings.analyzer_rules_root))
        database.record_engine_snapshot(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            engine_name=ENGINE_NAME,
            engine_version=engine_version,
            rulepack_name=RULEPACK_NAME,
            rulepack_manifest=rulepack_manifest,
        )
        manifest = inspect_archive(
            scan.archive_data,
            max_entries=settings.max_archive_entries,
            max_extracted_bytes=settings.max_extracted_bytes,
        )
        manifest_nodes = build_scan_file_manifest(manifest)
        manifest_summary = validate_scan_file_manifest(manifest_nodes, [])
        # ZIP entries + extracted source files + Semgrep + 49 normalized items + persistence.
        total_units = len(manifest.entries) + len(manifest.files) + 1 + 49 + 1
        completed_units = len(manifest.entries)
        database.update_progress(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            phase="ZIP_VALIDATION",
            completed_units=completed_units,
            total_units=total_units,
            message=f"ZIP 항목 {len(manifest.entries)}개를 안전하게 검증했습니다.",
        )

        extracted_files = extract_archive(scan.archive_data, manifest, workspace)
        analysis_targets = discover_analysis_targets(workspace)
        expected_target_paths = {
            node.path for node in manifest_nodes if node.analysis_state is ScanFileState.TARGET
        }
        actual_target_paths = {path.relative_to(workspace).as_posix() for path in analysis_targets}
        if actual_target_paths != expected_target_paths:
            raise AnalyzerError("ZIP manifest와 실제 분석 대상 파일이 일치하지 않습니다.")
        detected_languages = list(manifest_summary.detected_languages)
        language_file_counts = manifest_summary.language_file_counts
        database.record_target_metadata(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            archive_file_count=manifest_summary.archive_file_count,
            analysis_file_count=manifest_summary.analysis_file_count,
            detected_languages=detected_languages,
            language_file_counts=language_file_counts,
            executed_rule_count=supported_rule_count(detected_languages, rulepack_manifest),
        )
        completed_units += len(extracted_files)
        database.update_progress(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            phase="LANGUAGE_DETECTION",
            completed_units=completed_units,
            total_units=total_units,
            message=f"분석 대상 파일 {len(analysis_targets)}개의 언어를 식별했습니다.",
            detected_languages=detected_languages,
        )

        database.update_progress(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            phase="ANALYZING",
            completed_units=completed_units,
            total_units=total_units,
            message=(
                "분석 대상 파일이 없어 Semgrep 실행을 건너뜁니다."
                if not analysis_targets
                else "등록된 SAST 보안 규칙을 실행하고 있습니다."
            ),
            detected_languages=detected_languages,
        )
        partial_parsing_paths: list[str] = []
        semgrep_results = (
            run_semgrep(
                workspace,
                Path(settings.analyzer_rules_root),
                settings.analysis_timeout_seconds,
                settings.analyzer_max_output_bytes,
                settings.analyzer_max_findings,
                settings.analysis_idle_timeout_seconds,
                settings.analysis_max_timeout_seconds,
                settings.analysis_heartbeat_seconds,
                lambda: database.renew_scan_lease(
                    scan.scan_id,
                    worker_id=scan.worker_id,
                    attempt=scan.attempts,
                ),
                partial_parsing_reporter=partial_parsing_paths.extend,
            )
            if analysis_targets
            else []
        )
        completed_units += 1
        database.update_progress(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            phase="ANALYZING",
            completed_units=completed_units,
            total_units=total_units,
            message="등록된 SAST 보안 규칙 실행을 완료했습니다.",
            detected_languages=detected_languages,
        )

        results = normalize_results(semgrep_results, detected_languages)
        issues = normalize_issues(semgrep_results, detected_languages, issue_model_version=2)
        manifest_nodes = attach_issue_counts(manifest_nodes, issues)
        completed_units += len(results)
        database.update_progress(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            phase="NORMALIZING",
            completed_units=completed_units,
            total_units=total_units,
            message="KISA 보안약점 49개 상위 결과를 정규화했습니다.",
            detected_languages=detected_languages,
        )
        _remove_attempt_workspace(workspace)
        database.complete_scan(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            detected_languages=detected_languages,
            results=results,
            issues=issues,
            rulepack_manifest=rulepack_manifest,
            manifest_nodes=manifest_nodes,
            completion_message=_completion_message(partial_parsing_paths),
        )
        logger.info("scan %s completed", scan.scan_id)
    except StaleScanLeaseError:
        logger.warning("scan %s lease was lost; discarding stale worker output", scan.scan_id)
    except WorkspaceCleanupError as exc:
        _fail_scan_if_owned(
            database,
            scan,
            _WORKSPACE_CLEANUP_ERROR_CODE,
            _WORKSPACE_CLEANUP_MESSAGE,
        )
        logger.exception("scan %s workspace cleanup failed: %s", scan.scan_id, exc)
    except ScanSnapshotConflictError as exc:
        _fail_scan_if_owned(database, scan, "ANALYZER_STATE_CONFLICT", str(exc))
        logger.error("scan %s immutable metadata conflict: %s", scan.scan_id, exc)
    except UnsafeArchiveError as exc:
        _fail_scan_if_owned(database, scan, "UNSAFE_ARCHIVE", str(exc))
        logger.warning("scan %s rejected: %s", scan.scan_id, exc)
    except (AnalyzerError, EngineIntegrityError, RulepackIntegrityError) as exc:
        _fail_scan_if_owned(database, scan, "ANALYZER_ERROR", str(exc))
        logger.exception("scan %s analyzer failure", scan.scan_id)
    except Exception:
        _fail_scan_if_owned(
            database,
            scan,
            "INTERNAL_ERROR",
            "분석 중 내부 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.",
        )
        logger.exception("scan %s failed", scan.scan_id)
    finally:
        if scan_workspace_root is not None:
            _best_effort_remove_attempt_workspace(workspace, scan.scan_id)
            _best_effort_remove_empty_scan_workspace_root(scan_workspace_root, scan.scan_id)


def _completion_message(partial_parsing_paths: Sequence[str]) -> str:
    if not partial_parsing_paths:
        return "분석이 완료되었습니다."
    preview_count = min(3, len(partial_parsing_paths))
    preview = " · ".join(
        path if len(path) <= 320 else f"…{path[-319:]}"
        for path in partial_parsing_paths[:preview_count]
    )
    remainder = len(partial_parsing_paths) - preview_count
    suffix = f" · 외 {remainder}개" if remainder else ""
    return (
        "분석이 완료되었습니다. 일부 파일을 완전히 해석하지 못했습니다"
        f"({len(partial_parsing_paths)}개). 해당 파일의 탐지 결과는 일부 누락될 수 있습니다: "
        f"{preview}{suffix}"
    )


def _remove_attempt_workspace(workspace: Path) -> None:
    try:
        shutil.rmtree(workspace)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WorkspaceCleanupError("deterministic attempt workspace could not be removed") from exc


def _prepare_attempt_workspace(
    scan: ClaimedScan, workspace: Path, scan_workspace_root: Path
) -> None:
    """Remove only data that is stale for this newly claimed attempt.

    A retry is the sole owner of its scan root because the database claim increments
    ``attempts`` before this function runs. Earlier workers only ever remove their
    own deterministic attempt directory, so they cannot delete the active retry.
    """
    if scan.attempts > 1:
        _remove_stale_scan_workspace_root(scan_workspace_root)
        return
    _remove_attempt_workspace(workspace)


def _remove_stale_scan_workspace_root(scan_workspace_root: Path) -> None:
    try:
        shutil.rmtree(scan_workspace_root)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WorkspaceCleanupError("stale scan workspace root could not be removed") from exc


def _scan_workspace_root(workspace_root: Path, scan: ClaimedScan, workspace: Path) -> Path:
    root = workspace_root.resolve()
    candidate = workspace_root / scan.scan_id
    if (
        not scan.scan_id
        or Path(scan.scan_id).name != scan.scan_id
        or scan.scan_id in {".", ".."}
        or candidate.parent != workspace_root
        or workspace.parent != candidate
        or candidate.resolve().parent != root
    ):
        raise WorkspaceCleanupError("scan workspace root is not an exact child of workspace root")
    return candidate


def _best_effort_remove_attempt_workspace(workspace: Path, scan_id: str) -> None:
    try:
        _remove_attempt_workspace(workspace)
    except WorkspaceCleanupError:
        logger.exception("scan %s final workspace cleanup failed", scan_id)


def _best_effort_remove_empty_scan_workspace_root(scan_workspace_root: Path, scan_id: str) -> None:
    try:
        scan_workspace_root.rmdir()
    except FileNotFoundError:
        return
    except OSError:
        # A concurrent retry can own a sibling attempt directory. Never remove the
        # parent recursively; keep its contents fenced and make the condition visible.
        logger.info("scan %s left non-empty workspace root %s", scan_id, scan_workspace_root)


def reap_terminal_workspace_roots(database: Database, workspace_root: Path) -> None:
    """Remove only exact direct scan roots whose database state is terminal.

    This is recovery for hard-killed workers that never entered ``finally``. It
    deliberately does not inspect or remove active, unknown, malformed, or
    symlinked paths, and a failed deletion remains visible for the next pass.
    """
    try:
        root = workspace_root.resolve(strict=True)
        if workspace_root.is_symlink() or not root.is_dir():
            logger.error("configured workspace root is not a safe directory")
            return
        candidates = list(root.iterdir())
    except OSError:
        logger.exception("could not enumerate configured workspace root")
        return

    for candidate in candidates:
        scan_id = _trusted_scan_workspace_id(root, candidate)
        if scan_id is None:
            continue
        try:
            if not database.is_scan_workspace_reapable(scan_id):
                continue
        except Exception:
            logger.exception("could not verify terminal workspace for scan %s", scan_id)
            continue
        try:
            shutil.rmtree(candidate)
        except FileNotFoundError:
            continue
        except OSError:
            logger.exception("scan %s terminal workspace cleanup failed", scan_id)
            continue
        try:
            database.clear_deleted_scan_workspace(scan_id)
        except Exception:
            logger.exception("scan %s deletion tombstone cleanup failed", scan_id)
        logger.info("reaped terminal workspace for scan %s", scan_id)

    try:
        deleted_scan_ids = database.list_deleted_scan_workspaces()
    except Exception:
        logger.exception("could not enumerate deleted scan workspace tombstones")
        return
    for scan_id in deleted_scan_ids:
        if (root / scan_id).exists():
            continue
        try:
            database.clear_deleted_scan_workspace(scan_id)
        except Exception:
            logger.exception("scan %s deletion tombstone cleanup failed", scan_id)


def _trusted_scan_workspace_id(workspace_root: Path, candidate: Path) -> str | None:
    if candidate.parent != workspace_root or candidate.is_symlink() or not candidate.is_dir():
        return None
    try:
        scan_id = UUID(candidate.name)
        resolved = candidate.resolve(strict=True)
    except (OSError, ValueError):
        return None
    if str(scan_id) != candidate.name or resolved != workspace_root / candidate.name:
        return None
    return candidate.name


def _workspace_for_scan(workspace_root: Path, scan: ClaimedScan) -> Path:
    owner_fingerprint = hashlib.sha256(scan.worker_id.encode()).hexdigest()[:12]
    return workspace_root / scan.scan_id / f"attempt-{scan.attempts}-{owner_fingerprint}"


def _fail_scan_if_owned(
    database: Database, scan: ClaimedScan, error_code: str, message: str
) -> None:
    try:
        database.fail_scan(
            scan.scan_id,
            worker_id=scan.worker_id,
            attempt=scan.attempts,
            error_code=error_code,
            message=message,
        )
    except StaleScanLeaseError:
        logger.warning("scan %s lease was lost before failure could be recorded", scan.scan_id)


def main() -> None:
    settings = get_settings()
    ready_marker = Path(tempfile.gettempdir()) / "worker-ready"
    ready_marker.unlink(missing_ok=True)
    validate_engine_version()
    validate_rulepack_manifest(Path(settings.analyzer_rules_root))
    wait_for_database(settings.database_url)
    database = Database(settings.database_url)
    database.ensure_schema()
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    ready_marker.touch()
    logger.info("worker ready as %s", worker_id)
    next_workspace_janitor_at = 0.0
    while True:
        if time.monotonic() >= next_workspace_janitor_at:
            reap_terminal_workspace_roots(database, Path(settings.workspace_root))
            next_workspace_janitor_at = time.monotonic() + _WORKSPACE_JANITOR_INTERVAL_SECONDS
        scan = database.claim_next_scan(
            worker_id,
            lease_seconds=settings.scan_job_lease_seconds,
            max_attempts=settings.scan_max_attempts,
        )
        if scan is None:
            time.sleep(settings.worker_poll_seconds)
            continue
        process_scan(database, scan, settings)


if __name__ == "__main__":
    main()
