import json
import shutil
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

import app.analyzer as analyzer
from app.analyzer import (
    AnalyzerError,
    _parse_semgrep_output,
    _read_bounded_output,
    _semgrep_command,
    _terminate_process_group,
    discover_analysis_targets,
    identify_language,
    issue_fingerprint,
    issue_id_for,
    normalize_issues,
    normalize_language_results,
    normalize_results,
    run_semgrep,
    supported_rule_count,
)
from app.catalog import KISA_CATALOG, ImplementationStatus
from app.database import StaleScanLeaseError
from app.rule_registry import (
    RULE_REGISTRY,
    RULEPACK_VERSION,
    RULESET_DIGEST,
    FindingKind,
    RulepackIntegrityError,
    validate_rulepack_manifest,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGED_RULES_ROOT = PROJECT_ROOT / "analyzer" / "rules"


def test_normalizes_kisa_findings_without_claiming_full_support() -> None:
    semgrep_results = [
        {
            "check_id": "kisa-2021-02-python-code-injection",
            "path": "src/app.py",
            "start": {"line": 7},
            "extra": {"message": "동적 코드 실행", "severity": "ERROR"},
        }
    ]

    results = normalize_results(semgrep_results, ["Python"])

    assert len(results) == 49
    code_injection = results[1]
    assert code_injection["weakness_id"] == "KISA-2021-02"
    assert code_injection["description"]
    assert code_injection["implementation_status"] == "PARTIALLY_IMPLEMENTED"
    assert code_injection["support_status"] == "PARTIALLY_SUPPORTED"
    assert code_injection["result_status"] == "DETECTED"
    assert code_injection["finding_count"] == 1
    assert code_injection["findings"][0]["kind"] == "DETECTED"
    assert results[0]["result_status"] == "REVIEW_REQUIRED"


def test_normalization_rejects_unregistered_slug_and_namespace() -> None:
    findings = [
        {"check_id": "kisa-2021-02-python-invented", "path": "a.py"},
        {"check_id": "namespace.kisa-2021-02-python-code-injection", "path": "b.py"},
    ]

    with pytest.raises(AnalyzerError, match="등록되지 않은"):
        normalize_results(findings, ["Python"])


def test_normalization_rejects_finding_for_undetected_language() -> None:
    with pytest.raises(AnalyzerError, match="분석 대상 언어"):
        normalize_results(
            [{"check_id": "kisa-2021-02-python-code-injection", "path": "a.py"}],
            ["Java"],
        )


def test_implemented_finding_reports_full_support(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = tuple(
        replace(item, implementation_status=ImplementationStatus.IMPLEMENTED)
        if item.number == 2
        else item
        for item in KISA_CATALOG
    )
    monkeypatch.setattr(analyzer, "KISA_CATALOG", catalog)

    results = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"}],
        ["Python"],
    )

    assert results[1]["support_status"] == "SUPPORTED"
    assert results[1]["result_status"] == "DETECTED"


def test_normalizes_manual_criteria_as_review_required() -> None:
    results = normalize_results([], ["Java"])

    authentication = results[17]
    assert authentication["weakness_id"] == "KISA-2021-18"
    assert authentication["implementation_status"] == "MANUAL_REVIEW_REQUIRED"
    assert authentication["support_status"] == "MANUAL_REVIEW_REQUIRED"
    assert authentication["result_status"] == "REVIEW_REQUIRED"


def test_manual_signal_finding_remains_review_required() -> None:
    results = normalize_results(
        [
            {
                "check_id": "kisa-2021-18-javascript-unprotected-sensitive-route",
                "path": "src/routes.js",
                "start": {"line": 12},
                "extra": {"message": "인증 미들웨어 확인 필요", "severity": "WARNING"},
            }
        ],
        ["JavaScript"],
    )

    authentication = results[17]
    assert authentication["support_status"] == "MANUAL_REVIEW_REQUIRED"
    assert authentication["result_status"] == "REVIEW_REQUIRED"
    assert authentication["finding_count"] == 1
    assert authentication["findings"][0]["kind"] == "REVIEW_SIGNAL"
    assert "위험 신호" in authentication["reason"]


def test_normalized_issues_are_source_free_and_have_stable_fingerprint_and_id() -> None:
    finding = {
        "check_id": "kisa-2021-02-python-code-injection",
        "path": "src/app.py",
        "start": {"line": 7, "col": 3},
        "end": {"line": 7, "col": 19},
        "extra": {
            "message": "dynamic execution..",
            "severity": "ERROR",
            "lines": "eval(user_input)",
            "metavars": {"$INPUT": "user_input"},
            "metadata": {"description": "Rule explanation..", "cwe": "CWE-95"},
        },
    }

    issues = normalize_issues([finding], ["Python"])

    assert len(issues) == 1
    issue = issues[0]
    assert issue.result_status == "DETECTED"
    assert issue.finding_kind is FindingKind.DETECTED
    assert issue.detection_basis_version == 1
    assert issue.confidence == "MEDIUM"
    assert issue.rule_id in issue.detection_rationale
    assert "Rule explanation" in issue.detection_rationale
    assert "dynamic execution" in issue.detection_rationale
    assert "규칙 설명: Rule explanation. 탐지 메시지: dynamic execution." in (
        issue.detection_rationale
    )
    assert ".." not in issue.detection_rationale
    assert issue.fingerprint == issue_fingerprint(
        rule_id=issue.rule_id,
        finding_kind=issue.finding_kind,
        language=issue.language,
        path=issue.path,
        start_line=issue.start_line,
        start_column=issue.start_column,
        end_line=issue.end_line,
        end_column=issue.end_column,
    )
    assert "eval(user_input)" not in issue.model_dump_json()
    assert "metavars" not in issue.model_dump_json()


def test_normalized_review_signal_has_low_source_free_detection_basis() -> None:
    finding = {
        "check_id": "kisa-2021-33-python-login-without-rate-limit",
        "path": "src/auth.py",
        "start": {"line": 10, "col": 1},
        "end": {"line": 10, "col": 8},
        "extra": {
            "message": "rate limit signal",
            "severity": "INFO",
            "metadata": {"description": "Manual authentication review"},
        },
    }

    issue = normalize_issues([finding], ["Python"])[0]

    assert issue.finding_kind is FindingKind.REVIEW_SIGNAL
    assert issue.result_status == "REVIEW_REQUIRED"
    assert issue.detection_basis_version == 1
    assert issue.confidence == "LOW"
    assert "수동 검토 신호" in issue.detection_rationale
    assert "rate limit signal" in issue.detection_rationale
    assert "source" not in issue.model_dump()


def test_normalized_issue_fingerprint_uses_nul_separated_location_fields() -> None:
    base = issue_fingerprint(
        rule_id="kisa-2021-02-python-code-injection",
        finding_kind=FindingKind.DETECTED,
        language="Python",
        path="src/app.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=5,
    )
    assert base == "b5b8f15446ce6d34c6d1c1c694df53b8b252a8974cc05a2745a2cc821d528621"
    assert issue_id_for("52f03ca1-2434-40e3-9c3e-c0c598571cb8", base) == (
        "2278683e-1af4-5680-b8b0-db119a3b68f2"
    )
    assert base != issue_fingerprint(
        rule_id="kisa-2021-02-python-code-injection",
        finding_kind=FindingKind.DETECTED,
        language="Python",
        path="src/app.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=6,
    )


def test_normalized_issue_rejects_malformed_semgrep_location() -> None:
    with pytest.raises(AnalyzerError, match="위치"):
        normalize_issues(
            [
                {
                    "check_id": "kisa-2021-02-python-code-injection",
                    "path": "src/app.py",
                    "start": {"line": 1},
                    "end": {"line": 1, "col": 1},
                    "extra": {"message": "detected", "severity": "ERROR"},
                }
            ],
            ["Python"],
        )


def test_counts_only_rules_available_for_detected_languages() -> None:
    manifest = validate_rulepack_manifest(PACKAGED_RULES_ROOT)

    assert manifest.digest == RULESET_DIGEST
    assert supported_rule_count(["Java"], manifest) == 31
    assert supported_rule_count(["JavaScript"], manifest) == 23
    assert supported_rule_count(["Python"], manifest) == 25
    assert supported_rule_count(["Java", "JavaScript", "Python"], manifest) == 79
    assert len(RULE_REGISTRY) == 86
    assert RULEPACK_VERSION == "kisa-2021-v2"


def test_v2_language_results_are_complete_and_exclude_review_signals() -> None:
    review_signal = {
        "check_id": "kisa-2021-33-python-login-without-rate-limit",
        "path": "auth.py",
    }
    detected = {
        "check_id": "kisa-2021-02-python-code-injection",
        "path": "app.py",
    }

    rows = normalize_language_results([review_signal, detected], ["Python"])

    assert len(rows) == 49
    assert rows[1].result_status == "DETECTED"
    assert rows[1].finding_count == 1
    assert rows[32].support_status == "NOT_SUPPORTED"
    assert rows[32].result_status == "NOT_SUPPORTED"
    assert rows[32].executed_rule_count == 0


def test_v2_issue_normalization_drops_historical_review_signals() -> None:
    finding = {
        "check_id": "kisa-2021-33-python-login-without-rate-limit",
        "path": "auth.py",
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 5},
        "extra": {"message": "review", "severity": "INFO"},
    }

    assert normalize_issues([finding], ["Python"], issue_model_version=2) == []


def test_rulepack_manifest_rejects_yaml_content_drift(tmp_path: Path) -> None:
    copied_rules_root = tmp_path / "rules"
    copied_rulepack = copied_rules_root / "kisa-2021"
    shutil.copytree(PACKAGED_RULES_ROOT / "kisa-2021", copied_rulepack)
    java_rules = copied_rulepack / "java.yml"
    java_rules.write_text(java_rules.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(RulepackIntegrityError, match="내용"):
        validate_rulepack_manifest(copied_rules_root)


def test_rulepack_manifest_rejects_extra_yaml_file(tmp_path: Path) -> None:
    copied_rules_root = tmp_path / "rules"
    copied_rulepack = copied_rules_root / "kisa-2021"
    shutil.copytree(PACKAGED_RULES_ROOT / "kisa-2021", copied_rulepack)
    (copied_rulepack / "unregistered.yml").write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(RulepackIntegrityError, match="파일 구성"):
        validate_rulepack_manifest(copied_rules_root)


def test_semgrep_command_disables_all_source_suppressions(tmp_path: Path) -> None:
    command = _semgrep_command(tmp_path / "workspace", tmp_path / "rules")

    assert command[:2] == ("semgrep", "scan")
    for option in (
        "--disable-nosem",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--no-rewrite-rule-ids",
        "--strict",
        "--max-target-bytes=0",
        "--timeout=0",
        "--timeout-threshold=0",
    ):
        assert option in command
    for excluded_directory in ("node_modules", "dist", "build", "target", "vendor", ".venv"):
        assert ("--exclude", f"**/{excluded_directory}/**") in tuple(
            zip(command, command[1:], strict=False)
        )
    assert not any("manual-review-signals.yml" in argument for argument in command)
    assert sum(argument == "--config" for argument in command) == 5


def test_run_semgrep_returns_empty_without_process_when_no_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "README.txt").write_text("metadata only", encoding="utf-8")

    def unexpected_process(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Semgrep must not start when there are no supported targets")

    monkeypatch.setattr("app.analyzer.subprocess.Popen", unexpected_process)

    assert run_semgrep(tmp_path, tmp_path, 30, 1024, 100) == []


def test_discovers_typescript_but_excludes_generated_and_vendor_trees(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    source = workspace / "src" / "handler.tsx"
    source.parent.mkdir(parents=True)
    source.write_text("export const handler = () => 'ok'\n", encoding="utf-8")
    for excluded in ("node_modules", "dist", "build", "target", "vendor", ".venv", "venv"):
        generated = workspace / excluded / "unsafe.py"
        generated.parent.mkdir(parents=True)
        generated.write_text("eval(user_input)\n", encoding="utf-8")

    assert identify_language(source) == "JavaScript"
    assert discover_analysis_targets(workspace) == frozenset({source.resolve()})


def test_rejects_semgrep_finding_count_over_limit() -> None:
    payload = _semgrep_payload(results=[{}, {}])

    with pytest.raises(AnalyzerError, match="결과 수"):
        _parse_semgrep_output(
            payload,
            max_findings=1,
            expected_targets=frozenset(),
            workspace=Path.cwd(),
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"errors": [{"message": "parse failed"}]}, "분석 오류"),
        ({"skipped_rules": [{"rule_id": "broken"}]}, "분석 규칙"),
        ({"paths": {"scanned": [], "skipped": [{"path": "ignored.py"}]}}, "건너뛰"),
        ({"paths": {"scanned": ["unexpected.py"]}}, "예상하지 않은"),
    ],
)
def test_semgrep_output_fails_closed(overrides: dict[str, object], message: str) -> None:
    payload: dict[str, object] = {"results": [], "errors": [], "paths": {"scanned": []}}
    payload.update(overrides)

    with pytest.raises(AnalyzerError, match=message):
        _parse_semgrep_output(
            json.dumps(payload).encode(),
            max_findings=10,
            expected_targets=frozenset(),
            workspace=Path.cwd(),
        )


def test_semgrep_output_requires_exact_scanned_targets(tmp_path: Path) -> None:
    target = (tmp_path / "app.py").resolve()
    payload = _semgrep_payload(scanned=[str(target)])

    assert (
        _parse_semgrep_output(
            payload,
            max_findings=10,
            expected_targets=frozenset({target}),
            workspace=tmp_path,
        )
        == []
    )


def test_semgrep_output_allows_only_partial_parsing_warnings(tmp_path: Path) -> None:
    target = (tmp_path / "broken.py").resolve()
    target.write_text("def incomplete(:\n", encoding="utf-8")
    partial_parsing_paths: list[str] = []
    payload = _semgrep_payload(
        scanned=[str(target)],
        errors=[
            {
                "code": 3,
                "level": "warn",
                "type": ["PartialParsing", []],
                "message": "partial parse",
                "path": str(target),
            }
        ],
    )

    assert (
        _parse_semgrep_output(
            payload,
            max_findings=10,
            expected_targets=frozenset({target}),
            workspace=tmp_path,
            partial_parsing_paths=partial_parsing_paths,
        )
        == []
    )
    assert partial_parsing_paths == ["broken.py"]


def test_run_semgrep_accepts_exit_three_only_for_partial_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = (tmp_path / "broken.py").resolve()
    target.write_text("def incomplete(:\n", encoding="utf-8")
    payload = _semgrep_payload(
        scanned=[str(target)],
        errors=[
            {
                "code": 3,
                "level": "warn",
                "type": ["PartialParsing", []],
                "message": "partial parse",
                "path": str(target),
            }
        ],
    ).decode()
    script = f"import sys; print({payload!r}); sys.exit(3)"
    monkeypatch.setattr(
        analyzer,
        "_semgrep_command",
        lambda _workspace, _rules_root: (sys.executable, "-c", script),
    )
    partial_parsing_paths: list[str] = []

    assert (
        run_semgrep(
            tmp_path,
            tmp_path,
            5,
            64 * 1024,
            10,
            partial_parsing_reporter=partial_parsing_paths.extend,
        )
        == []
    )
    assert partial_parsing_paths == ["broken.py"]


def test_run_semgrep_terminates_process_when_heartbeat_loses_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.py"
    target.write_text("print('active')\n", encoding="utf-8")
    monkeypatch.setattr(
        analyzer,
        "_semgrep_command",
        lambda _workspace, _rules_root: (
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
        ),
    )
    terminated_processes: list[subprocess.Popen[bytes]] = []
    terminate_process_group = analyzer._terminate_process_group

    def record_termination(process: subprocess.Popen[bytes]) -> None:
        terminate_process_group(process)
        terminated_processes.append(process)

    def lose_lease() -> None:
        raise StaleScanLeaseError("lease lost")

    monkeypatch.setattr(analyzer, "_terminate_process_group", record_termination)

    with pytest.raises(StaleScanLeaseError, match="lease lost"):
        run_semgrep(
            tmp_path,
            tmp_path,
            5,
            1024,
            10,
            idle_timeout_seconds=5,
            max_timeout_seconds=5,
            heartbeat_seconds=1,
            heartbeat=lose_lease,
        )

    assert len(terminated_processes) == 1
    assert terminated_processes[0].poll() is not None


def test_semgrep_output_normalizes_absolute_finding_path_to_workspace_relative_posix(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / "src" / "handler.tsx"
    target.parent.mkdir(parents=True)
    target.write_text("eval(input)\n", encoding="utf-8")
    payload = _semgrep_payload(
        scanned=[str(target.resolve())],
        results=[{"check_id": "rule-id", "path": str(target.resolve())}],
    )

    parsed = _parse_semgrep_output(
        payload,
        max_findings=10,
        expected_targets=frozenset({target.resolve()}),
        workspace=workspace,
    )

    assert parsed[0]["path"] == "src/handler.tsx"


def test_semgrep_output_rejects_finding_outside_scanned_targets(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / "src" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_text("print('ok')\n", encoding="utf-8")
    payload = _semgrep_payload(
        scanned=[str(target.resolve())],
        results=[{"check_id": "rule-id", "path": str(tmp_path / "outside.py")}],
    )

    with pytest.raises(AnalyzerError, match="예상하지 않은"):
        _parse_semgrep_output(
            payload,
            max_findings=10,
            expected_targets=frozenset({target.resolve()}),
            workspace=workspace,
        )


def _semgrep_payload(
    *,
    results: list[object] | None = None,
    scanned: list[str] | None = None,
    errors: list[object] | None = None,
) -> bytes:
    return json.dumps(
        {
            "results": results or [],
            "errors": errors or [],
            "paths": {"scanned": scanned or []},
        }
    ).encode()


def test_rejects_semgrep_output_over_byte_limit() -> None:
    process = subprocess.Popen(  # noqa: S603 -- fixed Python executable and script
        [sys.executable, "-c", "print('x' * 1024)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        with pytest.raises(AnalyzerError, match="결과 크기"):
            _read_bounded_output(process, timeout_seconds=5, max_output_bytes=32)
    finally:
        _terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def test_terminates_semgrep_process_group_including_children(tmp_path: Path) -> None:
    marker = tmp_path / "child-survived"
    child_script = (
        "import pathlib,sys,time; time.sleep(0.3); pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent_script = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
        "print('ready', flush=True); time.sleep(60)"
    )
    process = subprocess.Popen(  # noqa: S603 -- fixed Python executable and scripts
        [sys.executable, "-c", parent_script, child_script, str(marker)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == b"ready"
        _terminate_process_group(process)
        time.sleep(0.5)
        assert not marker.exists()
    finally:
        _terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def test_terminates_children_after_semgrep_parent_already_exited(tmp_path: Path) -> None:
    marker = tmp_path / "orphan-child-survived"
    child_script = (
        "import pathlib,sys,time; time.sleep(0.3); pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent_script = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
    )
    process = subprocess.Popen(  # noqa: S603 -- fixed Python executable and scripts
        [sys.executable, "-c", parent_script, child_script, str(marker)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        process.wait(timeout=5)
        assert process.returncode == 0
        _terminate_process_group(process)
        time.sleep(0.5)
        assert not marker.exists()
    finally:
        _terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def test_timeout_still_applies_after_process_closes_output_streams() -> None:
    process = subprocess.Popen(  # noqa: S603 -- fixed Python executable and script
        [
            sys.executable,
            "-c",
            "import os,time; os.close(1); os.close(2); time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        with pytest.raises(AnalyzerError, match="분석 시간"):
            _read_bounded_output(process, timeout_seconds=1, max_output_bytes=1024)
    finally:
        _terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def test_active_analysis_extends_the_initial_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = subprocess.Popen(  # noqa: S603 -- fixed Python executable and script
        [sys.executable, "-c", "import time; time.sleep(0.25); print('done')"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    heartbeats = 0

    def record_heartbeat() -> None:
        nonlocal heartbeats
        heartbeats += 1

    monkeypatch.setattr(
        analyzer,
        "_process_group_cpu_seconds",
        lambda _process: time.monotonic(),
    )
    try:
        stdout, _stderr = _read_bounded_output(
            process,
            timeout_seconds=0.05,
            idle_timeout_seconds=0.1,
            max_timeout_seconds=1,
            heartbeat_seconds=0.02,
            heartbeat=record_heartbeat,
            max_output_bytes=1024,
        )
    finally:
        _terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    assert stdout.strip() == b"done"
    assert heartbeats > 1


def test_active_analysis_still_stops_at_the_absolute_maximum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = subprocess.Popen(  # noqa: S603 -- fixed Python executable and script
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    monkeypatch.setattr(
        analyzer,
        "_process_group_cpu_seconds",
        lambda _process: time.monotonic(),
    )
    try:
        with pytest.raises(AnalyzerError, match="최대 실행시간"):
            _read_bounded_output(
                process,
                timeout_seconds=0.05,
                idle_timeout_seconds=0.1,
                max_timeout_seconds=0.15,
                heartbeat_seconds=0.02,
                max_output_bytes=1024,
            )
    finally:
        _terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
