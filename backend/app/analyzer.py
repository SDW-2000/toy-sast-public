import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast
from uuid import UUID, uuid5

from app.catalog import KISA_CATALOG, ImplementationStatus
from app.rule_registry import (
    RULE_LANGUAGE_SUPPORT,
    RULE_REGISTRY,
    RULEPACK_FILES,
    RULEPACK_VERSION,
    RULESET_DIGEST,
    VERIFIED_DETECTED_RULE_REGISTRY,
    VERIFIED_RULE_SUPPORT_MATRIX,
    FindingKind,
    RulepackIntegrityError,
    RulepackManifest,
)
from app.schemas import (
    IssueConfidence,
    IssueSeverity,
    JsonObject,
    LanguageCoverageResult,
    NormalizedIssue,
    ResultStatus,
)


class AnalyzerError(RuntimeError):
    pass


ISSUE_FINGERPRINT_VERSION = 1
ISSUE_FINGERPRINT_DOMAIN = "toy-sast:issue-fingerprint:v1"
ISSUE_ID_NAMESPACE = UUID("7c71d2db-aafd-5c81-8e6a-02d2ab74f586")
_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]{0,5}$")


LANGUAGE_SUFFIXES: dict[str, frozenset[str]] = {
    "Java": frozenset({".java"}),
    "JavaScript": frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    "Python": frozenset({".py"}),
}
EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        ".cache",
        ".git",
        ".mypy_cache",
        ".next",
        ".nox",
        ".nuxt",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
        "vendor",
        "venv",
    }
)


def identify_language(path: Path) -> str | None:
    suffix = path.suffix.lower()
    for language, suffixes in LANGUAGE_SUFFIXES.items():
        if suffix in suffixes:
            return language
    return None


def run_semgrep(
    workspace: Path,
    rules_root: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    max_findings: int,
    idle_timeout_seconds: int | None = None,
    max_timeout_seconds: int | None = None,
    heartbeat_seconds: int | None = None,
    heartbeat: Callable[[], None] | None = None,
    partial_parsing_reporter: Callable[[tuple[str, ...]], None] | None = None,
) -> list[JsonObject]:
    command = _semgrep_command(workspace, rules_root)
    expected_targets = discover_analysis_targets(workspace)
    # Semgrep exits non-zero when the workspace contains no supported targets. A
    # non-empty archive containing only unsupported or explicitly excluded files is
    # nevertheless a valid scan, so normalize it without starting the subprocess.
    if not expected_targets:
        return []
    try:
        process = subprocess.Popen(  # noqa: S603 -- fixed executable and arguments
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise AnalyzerError("Semgrep 분석기를 실행하지 못했습니다.") from exc
    try:
        stdout, _stderr = _read_bounded_output(
            process,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            idle_timeout_seconds=idle_timeout_seconds,
            max_timeout_seconds=max_timeout_seconds,
            heartbeat_seconds=heartbeat_seconds,
            heartbeat=heartbeat,
        )
    except Exception:
        _terminate_process_group(process)
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if process.returncode not in (0, 1, 3):
        raise AnalyzerError("Semgrep 분석기가 오류를 반환했습니다.")
    partial_parsing_paths: list[str] = []
    results = _parse_semgrep_output(
        stdout,
        max_findings=max_findings,
        expected_targets=expected_targets,
        workspace=workspace,
        partial_parsing_paths=partial_parsing_paths,
    )
    if process.returncode == 3 and not partial_parsing_paths:
        raise AnalyzerError("Semgrep 분석기가 오류를 반환했습니다.")
    if partial_parsing_paths and partial_parsing_reporter is not None:
        partial_parsing_reporter(tuple(partial_parsing_paths))
    return results


def _semgrep_command(workspace: Path, rules_root: Path) -> tuple[str, ...]:
    exclusions = tuple(
        argument
        for directory_name in sorted(EXCLUDED_DIRECTORY_NAMES)
        for argument in ("--exclude", f"**/{directory_name}/**")
    )
    verified_configs = tuple(
        argument
        for filename in RULEPACK_FILES
        if filename != "manual-review-signals.yml"
        for argument in ("--config", str(rules_root / "kisa-2021" / filename))
    )
    return (
        "semgrep",
        "scan",
        "--disable-version-check",
        "--metrics=off",
        "--disable-nosem",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--no-rewrite-rule-ids",
        "--strict",
        "--max-target-bytes=0",
        "--timeout=0",
        "--timeout-threshold=0",
        *exclusions,
        *verified_configs,
        "--json",
        str(workspace),
    )


def discover_analysis_targets(workspace: Path) -> frozenset[Path]:
    workspace_resolved = workspace.resolve()
    return frozenset(
        path.resolve()
        for path in workspace_resolved.rglob("*")
        if path.is_file()
        and identify_language(path) is not None
        and not (set(path.relative_to(workspace_resolved).parts[:-1]) & EXCLUDED_DIRECTORY_NAMES)
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _process_group_cpu_seconds(process: subprocess.Popen[bytes]) -> float | None:
    """Return Linux process-group CPU time, or None when /proc is unavailable."""
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return None
    total_ticks = 0
    found = False
    for stat_path in proc_root.glob("[0-9]*/stat"):
        try:
            raw = stat_path.read_text(encoding="utf-8")
            fields = raw[raw.rfind(")") + 2 :].split()
            if len(fields) < 13 or int(fields[2]) != process.pid:
                continue
            total_ticks += int(fields[11]) + int(fields[12])
            found = True
        except (OSError, ValueError):
            continue
    if not found:
        return None
    return total_ticks / float(os.sysconf("SC_CLK_TCK"))


def _read_bounded_output(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    idle_timeout_seconds: float | None = None,
    max_timeout_seconds: float | None = None,
    heartbeat_seconds: float | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise AnalyzerError("Semgrep 출력 스트림을 열지 못했습니다.")
    idle_timeout = timeout_seconds if idle_timeout_seconds is None else idle_timeout_seconds
    hard_timeout = timeout_seconds if max_timeout_seconds is None else max_timeout_seconds
    if timeout_seconds <= 0 or idle_timeout <= 0:
        raise ValueError("analysis timeouts must be positive")
    if hard_timeout < timeout_seconds:
        raise ValueError("max_timeout_seconds must be at least timeout_seconds")
    if heartbeat_seconds is not None and heartbeat_seconds <= 0:
        raise ValueError("heartbeat_seconds must be positive")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout = bytearray()
    stderr = bytearray()
    started_at = time.monotonic()
    initial_deadline = started_at + timeout_seconds
    activity_deadline = initial_deadline
    hard_deadline = started_at + hard_timeout
    last_activity_at = started_at
    last_cpu_seconds = _process_group_cpu_seconds(process)
    next_heartbeat_at = (
        started_at + heartbeat_seconds if heartbeat_seconds is not None else float("inf")
    )

    def remaining_time(now: float) -> float:
        deadline = min(activity_deadline, hard_deadline)
        if now < deadline:
            return deadline - now
        if now >= hard_deadline:
            raise AnalyzerError("Semgrep 분석 시간이 최대 실행시간을 초과했습니다.")
        if now - last_activity_at >= idle_timeout:
            raise AnalyzerError("Semgrep 분석 활동을 확인하지 못해 중단했습니다.")
        raise AnalyzerError("Semgrep 분석 시간이 허용 범위를 초과했습니다.")

    def record_activity(now: float) -> None:
        nonlocal activity_deadline, last_activity_at
        last_activity_at = now
        activity_deadline = min(hard_deadline, max(activity_deadline, now + idle_timeout))

    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            remaining = remaining_time(now)
            wait_seconds = min(0.25, remaining, max(0.0, next_heartbeat_at - now))
            events = selector.select(timeout=wait_seconds) if selector.get_map() else ()
            if not selector.get_map() and wait_seconds > 0:
                time.sleep(wait_seconds)
            for key, _events in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                record_activity(time.monotonic())
                if len(stdout) + len(stderr) + len(chunk) > max_output_bytes:
                    raise AnalyzerError("Semgrep 결과 크기가 허용 범위를 초과했습니다.")
                if key.data == "stdout":
                    stdout.extend(chunk)
                else:
                    stderr.extend(chunk)
            now = time.monotonic()
            if now >= next_heartbeat_at:
                current_cpu_seconds = _process_group_cpu_seconds(process)
                if (
                    current_cpu_seconds is not None
                    and last_cpu_seconds is not None
                    and current_cpu_seconds > last_cpu_seconds
                ):
                    record_activity(now)
                if current_cpu_seconds is not None:
                    last_cpu_seconds = current_cpu_seconds
                if heartbeat is not None:
                    heartbeat()
                next_heartbeat_at = now + (heartbeat_seconds or hard_timeout)
        process.wait()
    finally:
        selector.close()
    return bytes(stdout), bytes(stderr)


def _parse_semgrep_output(
    output: bytes,
    *,
    max_findings: int,
    expected_targets: frozenset[Path],
    workspace: Path,
    partial_parsing_paths: list[str] | None = None,
) -> list[JsonObject]:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AnalyzerError("Semgrep 결과를 해석하지 못했습니다.") from exc
    if not isinstance(payload, dict):
        raise AnalyzerError("Semgrep 결과 형식이 올바르지 않습니다.")
    errors = payload.get("errors")
    if not isinstance(errors, list):
        raise AnalyzerError("Semgrep 결과에 분석 오류가 포함되어 있습니다.")
    tolerated_partial_parsing_paths = _validated_partial_parsing_paths(
        errors,
        expected_targets=expected_targets,
        workspace=workspace,
    )
    if partial_parsing_paths is not None:
        partial_parsing_paths.extend(tolerated_partial_parsing_paths)
    skipped_rules = payload.get("skipped_rules", [])
    if not isinstance(skipped_rules, list) or skipped_rules:
        raise AnalyzerError("Semgrep이 등록된 분석 규칙을 건너뛰었습니다.")
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise AnalyzerError("Semgrep 대상 경로 결과가 누락되었습니다.")
    for skipped in (payload.get("skipped", []), paths.get("skipped", [])):
        if not isinstance(skipped, list) or skipped:
            raise AnalyzerError("Semgrep이 분석 대상 파일을 건너뛰었습니다.")
    scanned = paths.get("scanned")
    if not isinstance(scanned, list) or not all(isinstance(path, str) for path in scanned):
        raise AnalyzerError("Semgrep 대상 경로 결과가 올바르지 않습니다.")
    scanned_targets = frozenset(
        _resolve_semgrep_target(path, workspace=workspace, expected_targets=expected_targets)
        for path in scanned
    )
    if len(scanned) != len(scanned_targets) or scanned_targets != expected_targets:
        raise AnalyzerError("Semgrep이 예상 분석 대상 파일 전체를 처리하지 않았습니다.")
    results = payload.get("results")
    if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
        raise AnalyzerError("Semgrep 결과 형식이 올바르지 않습니다.")
    if len(results) > max_findings:
        raise AnalyzerError("Semgrep 발견 결과 수가 허용 범위를 초과했습니다.")
    normalized_results: list[JsonObject] = []
    workspace_resolved = workspace.resolve()
    for item in results:
        reported_path = item.get("path")
        if not isinstance(reported_path, str) or not reported_path:
            raise AnalyzerError("Semgrep 발견 결과의 대상 경로가 올바르지 않습니다.")
        resolved_path = _resolve_semgrep_target(
            reported_path,
            workspace=workspace_resolved,
            expected_targets=expected_targets,
        )
        try:
            relative_path = resolved_path.relative_to(workspace_resolved).as_posix()
        except ValueError as exc:
            raise AnalyzerError("Semgrep 발견 결과가 분석 작업공간 밖을 가리킵니다.") from exc
        normalized_item = dict(item)
        normalized_item["path"] = relative_path
        normalized_results.append(cast(JsonObject, normalized_item))
    return normalized_results


def _validated_partial_parsing_paths(
    errors: list[object],
    *,
    expected_targets: frozenset[Path],
    workspace: Path,
) -> tuple[str, ...]:
    workspace_resolved = workspace.resolve()
    paths: set[str] = set()
    for error in errors:
        if not isinstance(error, dict):
            raise AnalyzerError("Semgrep 결과에 분석 오류가 포함되어 있습니다.")
        error_type = error.get("type")
        reported_path = error.get("path")
        if (
            error.get("code") != 3
            or error.get("level") != "warn"
            or not isinstance(error_type, list)
            or not error_type
            or error_type[0] != "PartialParsing"
            or not isinstance(reported_path, str)
            or not reported_path
        ):
            raise AnalyzerError("Semgrep 결과에 분석 오류가 포함되어 있습니다.")
        resolved_path = _resolve_semgrep_target(
            reported_path,
            workspace=workspace_resolved,
            expected_targets=expected_targets,
        )
        paths.add(resolved_path.relative_to(workspace_resolved).as_posix())
    return tuple(sorted(paths, key=lambda path: path.encode("utf-8")))


def _resolve_semgrep_target(
    reported_path: str,
    *,
    workspace: Path,
    expected_targets: frozenset[Path],
) -> Path:
    path = Path(reported_path)
    candidates = (
        {path.resolve()}
        if path.is_absolute()
        else {
            path.resolve(),
            (workspace / path).resolve(),
        }
    )
    matching_targets = candidates & expected_targets
    if len(matching_targets) != 1:
        raise AnalyzerError("Semgrep이 예상하지 않은 분석 대상 경로를 반환했습니다.")
    return next(iter(matching_targets))


def normalize_results(
    semgrep_results: Sequence[JsonObject], detected_languages: Sequence[str]
) -> list[JsonObject]:
    present_languages = set(detected_languages)
    findings_by_weakness: dict[int, list[JsonObject]] = defaultdict(list)
    for item in semgrep_results:
        rule_id = str(item.get("check_id", ""))
        registration = RULE_REGISTRY.get(rule_id)
        if registration is None:
            raise AnalyzerError(f"등록되지 않은 Semgrep 룰 ID입니다: {rule_id}")
        weakness_number = registration.weakness_number
        language = registration.language
        if language not in present_languages:
            raise AnalyzerError("Semgrep 발견 결과의 언어가 분석 대상 언어와 일치하지 않습니다.")
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        findings_by_weakness[weakness_number].append(
            {
                "rule_id": rule_id,
                "kind": registration.finding_kind.value,
                "language": language,
                "path": str(item.get("path", "")),
                "start_line": int(cast(dict[str, Any], start).get("line", 1)),
                "message": str(cast(dict[str, Any], extra).get("message", "탐지됨")),
                "severity": str(cast(dict[str, Any], extra).get("severity", "WARNING")),
            }
        )

    results: list[JsonObject] = []
    for weakness in KISA_CATALOG:
        supported_languages = RULE_LANGUAGE_SUPPORT.get(weakness.number, frozenset())
        active_support = supported_languages & present_languages
        findings = findings_by_weakness.get(weakness.number, [])
        if weakness.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED:
            support_status = "MANUAL_REVIEW_REQUIRED"
            result_status = "REVIEW_REQUIRED"
            if findings:
                reason = (
                    "보조 SAST 규칙이 수동 검토가 필요한 위험 신호를 발견했습니다. "
                    "업무 정책과 실행 상태를 확인해 취약 여부를 판정해야 합니다."
                )
            elif active_support:
                reason = (
                    "보조 SAST 규칙에서 직접적인 위험 신호를 발견하지 못했지만, "
                    "업무 정책이나 실행 상태를 포함한 수동 검토가 필요합니다."
                )
            else:
                reason = (
                    "현재 분석 언어에는 보조 SAST 규칙이 없으며, 업무 정책이나 실행 상태를 "
                    "포함한 수동 검토가 필요합니다."
                )
        elif findings:
            result_status = "DETECTED"
            if weakness.implementation_status is ImplementationStatus.IMPLEMENTED:
                support_status = "SUPPORTED"
                reason = "구현된 SAST 규칙 범위에서 취약 패턴을 발견했습니다."
            else:
                support_status = "PARTIALLY_SUPPORTED"
                reason = "검증된 SAST 규칙의 제한된 탐지 범위에서 취약 패턴을 발견했습니다."
        elif active_support:
            if weakness.implementation_status is ImplementationStatus.IMPLEMENTED:
                support_status = "SUPPORTED"
                result_status = "NOT_DETECTED"
                reason = "구현된 규칙 범위에서 취약 패턴을 발견하지 못했습니다."
            else:
                support_status = "PARTIALLY_SUPPORTED"
                result_status = "REVIEW_REQUIRED"
                reason = (
                    "실행된 규칙에서는 패턴을 발견하지 못했지만, 부분 구현 범위 밖은 "
                    "수동 검토가 필요합니다."
                )
        else:
            support_status = "NOT_SUPPORTED"
            result_status = "NOT_SUPPORTED"
            reason = "현재 분석 언어에 실행 가능한 검증 룰이 아직 없습니다."
        results.append(
            {
                "weakness_id": weakness.weakness_id,
                "number": weakness.number,
                "category": weakness.category,
                "category_number": weakness.category_number,
                "name": weakness.name,
                "description": weakness.description,
                "sast_classification": weakness.sast_classification,
                "implementation_status": weakness.implementation_status.value,
                "support_status": support_status,
                "result_status": result_status,
                "reason": reason,
                "finding_count": len(findings),
                "findings": findings,
            }
        )
    return results


def normalize_issues(
    semgrep_results: Sequence[JsonObject],
    detected_languages: Sequence[str],
    *,
    issue_model_version: Literal[1, 2] = 1,
) -> list[NormalizedIssue]:
    """Normalize only persisted, source-free issue fields from verified Semgrep output."""

    present_languages = set(detected_languages)
    issues: list[NormalizedIssue] = []
    seen_fingerprints: set[str] = set()
    catalog_by_number = {item.number: item for item in KISA_CATALOG}
    for item in semgrep_results:
        rule_id = item.get("check_id")
        if not isinstance(rule_id, str) or not rule_id:
            raise AnalyzerError("Semgrep 발견 결과의 룰 ID가 올바르지 않습니다.")
        registration = RULE_REGISTRY.get(rule_id)
        if registration is None:
            raise AnalyzerError(f"등록되지 않은 Semgrep 룰 ID입니다: {rule_id}")
        if registration.language not in present_languages:
            raise AnalyzerError("Semgrep 발견 결과의 언어가 분석 대상 언어와 일치하지 않습니다.")
        if issue_model_version == 2 and registration.finding_kind is FindingKind.REVIEW_SIGNAL:
            # Historical review signals remain registered for v1 snapshot validation,
            # but they are not vulnerability issues under the v2 result contract.
            continue

        path = item.get("path")
        if not isinstance(path, str) or not _is_normalized_issue_path(path):
            raise AnalyzerError("Semgrep 발견 결과의 경로가 안전한 상대 경로가 아닙니다.")
        start_line, start_column = _parse_position(item.get("start"), "시작")
        end_line, end_column = _parse_position(item.get("end"), "종료")
        if (end_line, end_column) < (start_line, start_column):
            raise AnalyzerError("Semgrep 발견 결과의 종료 위치가 시작 위치보다 앞섭니다.")

        extra = item.get("extra")
        if not isinstance(extra, dict):
            raise AnalyzerError("Semgrep 발견 결과의 상세 정보가 올바르지 않습니다.")
        message = extra.get("message")
        if not isinstance(message, str) or not message.strip() or len(message) > 4000:
            raise AnalyzerError("Semgrep 발견 결과의 메시지가 올바르지 않습니다.")
        severity_value = extra.get("severity")
        if not isinstance(severity_value, str):
            raise AnalyzerError("Semgrep 발견 결과의 심각도가 올바르지 않습니다.")
        try:
            severity = IssueSeverity(severity_value)
        except (TypeError, ValueError) as exc:
            raise AnalyzerError("Semgrep 발견 결과의 심각도가 올바르지 않습니다.") from exc

        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            raise AnalyzerError("Semgrep 룰 metadata가 올바르지 않습니다.")
        rule_description = _optional_metadata_text(metadata, "description", maximum_length=4000)
        cwe_id = _optional_metadata_text(metadata, "cwe", maximum_length=32)
        if cwe_id is not None and _CWE_PATTERN.fullmatch(cwe_id) is None:
            raise AnalyzerError("Semgrep 룰 CWE 식별자가 올바르지 않습니다.")

        weakness = catalog_by_number[registration.weakness_number]
        finding_kind = registration.finding_kind
        result_status: Literal[ResultStatus.DETECTED, ResultStatus.REVIEW_REQUIRED] = (
            ResultStatus.DETECTED
            if finding_kind is FindingKind.DETECTED
            else ResultStatus.REVIEW_REQUIRED
        )
        confidence, detection_rationale = issue_detection_snapshot(
            finding_kind=finding_kind,
            rule_id=rule_id,
            rule_description=rule_description,
            message=message,
        )
        fingerprint = issue_fingerprint(
            rule_id=rule_id,
            finding_kind=finding_kind,
            language=registration.language,
            path=path,
            start_line=start_line,
            start_column=start_column,
            end_line=end_line,
            end_column=end_column,
        )
        if fingerprint in seen_fingerprints:
            raise AnalyzerError("동일한 Semgrep finding이 중복 반환되었습니다.")
        seen_fingerprints.add(fingerprint)
        issues.append(
            NormalizedIssue(
                fingerprint=fingerprint,
                result_status=result_status,
                finding_kind=finding_kind,
                confidence=confidence,
                detection_rationale=detection_rationale,
                severity=severity,
                weakness_id=weakness.weakness_id,
                weakness_number=weakness.number,
                weakness_name=weakness.name,
                weakness_category=weakness.category,
                weakness_category_number=weakness.category_number,
                weakness_description=weakness.description,
                sast_classification=weakness.sast_classification,
                implementation_status=weakness.implementation_status,
                rule_id=rule_id,
                language=registration.language,
                path=path,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                message=message,
                rule_description=rule_description,
                cwe_id=cwe_id,
            )
        )
    return issues


def normalize_language_results(
    semgrep_results: Sequence[JsonObject], detected_languages: Sequence[str]
) -> list[LanguageCoverageResult]:
    """Build the v2 weakness-by-detected-language execution contract.

    REVIEW_SIGNAL registrations are deliberately absent from the verified support
    matrix.  Matches from those historical rules are validated for provenance and
    then ignored; they never become v2 issues or NOT_DETECTED support claims.
    """

    languages = tuple(detected_languages)
    if len(set(languages)) != len(languages) or not set(languages) <= {
        "Java",
        "JavaScript",
        "Python",
    }:
        raise AnalyzerError("분석 대상 언어 목록이 올바르지 않습니다.")
    detected_counts: Counter[tuple[int, str]] = Counter()
    for item in semgrep_results:
        rule_id = item.get("check_id")
        if not isinstance(rule_id, str) or not rule_id:
            raise AnalyzerError("Semgrep 발견 결과의 룰 ID가 올바르지 않습니다.")
        registration = RULE_REGISTRY.get(rule_id)
        if registration is None:
            raise AnalyzerError(f"등록되지 않은 Semgrep 룰 ID입니다: {rule_id}")
        if registration.language not in languages:
            raise AnalyzerError("Semgrep 발견 결과의 언어가 분석 대상 언어와 일치하지 않습니다.")
        if registration.finding_kind is FindingKind.DETECTED:
            detected_counts[(registration.weakness_number, registration.language)] += 1

    results: list[LanguageCoverageResult] = []
    for weakness in KISA_CATALOG:
        for language in languages:
            rule_ids = VERIFIED_RULE_SUPPORT_MATRIX[(weakness.number, language)]
            finding_count = detected_counts[(weakness.number, language)]
            if not rule_ids:
                results.append(
                    LanguageCoverageResult(
                        language=language,
                        support_status="NOT_SUPPORTED",
                        result_status="NOT_SUPPORTED",
                        executed_rule_count=0,
                        finding_count=0,
                        reason="해당 기준·언어에 fixture로 검증된 자동 탐지 룰이 없습니다.",
                    )
                )
                continue
            results.append(
                LanguageCoverageResult(
                    language=language,
                    support_status="SUPPORTED",
                    result_status="DETECTED" if finding_count else "NOT_DETECTED",
                    executed_rule_count=len(rule_ids),
                    finding_count=finding_count,
                    reason=(
                        "등록되고 검증된 자동 탐지 룰에서 코드 위치가 일치했습니다."
                        if finding_count
                        else "등록되고 검증된 자동 탐지 룰을 실행했으나 일치 항목이 없습니다."
                    ),
                )
            )
    return results


def issue_detection_snapshot(
    *,
    finding_kind: FindingKind,
    rule_id: str,
    rule_description: str | None,
    message: str,
) -> tuple[IssueConfidence, str]:
    """Derive the immutable, source-free detection explanation for issue model v1."""

    description = _detection_rationale_sentence(rule_description or "정보 없음")
    detection_message = _detection_rationale_sentence(message)
    if finding_kind is FindingKind.DETECTED:
        confidence = IssueConfidence.MEDIUM
        rationale = (
            f"규칙 {rule_id}이 저장된 규칙 설명과 탐지 메시지에 해당하는 위험 패턴을 "
            "탐지했습니다. 이 결과는 자동 패턴 일치 근거이며 실제 실행 가능성은 별도 "
            f"검증해야 합니다. 규칙 설명: {description} 탐지 메시지: {detection_message}"
        )
    else:
        confidence = IssueConfidence.LOW
        rationale = (
            f"규칙 {rule_id}이 저장된 규칙 설명과 탐지 메시지에 해당하는 수동 검토 "
            "신호를 식별했습니다. 이 신호만으로 취약 여부를 확정할 수 없으며 수동 "
            f"검증이 필요합니다. 규칙 설명: {description} 탐지 메시지: {detection_message}"
        )
    return confidence, rationale[:4000]


_DETECTION_RATIONALE_TERMINALS = ".!?。！？"


def _detection_rationale_sentence(value: str) -> str:
    """Return stored prose with one deterministic terminal punctuation mark."""

    trimmed = value.rstrip(" ")
    terminal = trimmed[-1] if trimmed and trimmed[-1] in _DETECTION_RATIONALE_TERMINALS else "."
    return f"{trimmed.rstrip(_DETECTION_RATIONALE_TERMINALS)}{terminal}"


def issue_fingerprint(
    *,
    rule_id: str,
    finding_kind: FindingKind,
    language: str,
    path: str,
    start_line: int,
    start_column: int,
    end_line: int,
    end_column: int,
) -> str:
    canonical = "\0".join(
        (
            ISSUE_FINGERPRINT_DOMAIN,
            rule_id,
            finding_kind.value,
            language,
            path,
            str(start_line),
            str(start_column),
            str(end_line),
            str(end_column),
        )
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def issue_id_for(scan_id: str, fingerprint: str) -> str:
    try:
        normalized_scan_id = str(UUID(scan_id))
    except ValueError as exc:
        raise ValueError("scan_id must be a UUID") from exc
    if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise ValueError("fingerprint must be a lowercase SHA-256 digest")
    return str(uuid5(ISSUE_ID_NAMESPACE, f"{normalized_scan_id}:{fingerprint}"))


def _parse_position(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise AnalyzerError(f"Semgrep 발견 결과의 {label} 위치가 누락되었습니다.")
    line = value.get("line")
    column = value.get("col")
    if type(line) is not int or type(column) is not int or line < 1 or column < 1:
        raise AnalyzerError(f"Semgrep 발견 결과의 {label} 위치가 올바르지 않습니다.")
    return line, column


def _optional_metadata_text(
    metadata: dict[object, object], key: str, *, maximum_length: int
) -> str | None:
    value = metadata.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum_length:
        raise AnalyzerError(f"Semgrep 룰 {key} metadata가 올바르지 않습니다.")
    return value


def _is_normalized_issue_path(path: str) -> bool:
    parsed = PurePosixPath(path)
    return bool(
        path
        and len(path.encode("utf-8")) <= 4096
        and "\\" not in path
        and not parsed.is_absolute()
        and all(part not in {"", ".", ".."} for part in parsed.parts)
        and parsed.as_posix() == path
    )


def supported_rule_count(detected_languages: Sequence[str], manifest: RulepackManifest) -> int:
    if (
        manifest.version != RULEPACK_VERSION
        or manifest.digest != RULESET_DIGEST
        or manifest.rule_ids != frozenset(RULE_REGISTRY)
    ):
        raise RulepackIntegrityError("검증되지 않은 KISA 2021 룰팩 manifest입니다.")
    present_languages = set(detected_languages)
    return sum(
        1
        for registration in VERIFIED_DETECTED_RULE_REGISTRY.values()
        if registration.language in present_languages
    )
