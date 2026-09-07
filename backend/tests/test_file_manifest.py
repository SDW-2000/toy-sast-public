from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from app.analyzer import discover_analysis_targets, normalize_results
from app.archive import inspect_archive
from app.file_manifest import (
    attach_finding_counts,
    build_scan_file_manifest,
    validate_scan_file_manifest,
)
from app.schemas import ScanFileNode, ScanFileState, WeaknessResult


def make_zip(entries: dict[str, bytes], directories: tuple[str, ...] = ()) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for directory in directories:
            archive.writestr(f"{directory.rstrip('/')}/", b"")
        for path, content in entries.items():
            archive.writestr(path, content)
    return output.getvalue()


def build(entries: dict[str, bytes], directories: tuple[str, ...] = ()) -> tuple[ScanFileNode, ...]:
    archive = inspect_archive(
        make_zip(entries, directories), max_entries=100, max_extracted_bytes=4096
    )
    return build_scan_file_manifest(archive)


def test_manifest_contains_explicit_and_synthetic_directories_with_classification() -> None:
    nodes = build(
        {
            "src/app.py": b"print('x')",
            "src/readme.txt": b"notes",
            "vendor/lib.js": b"eval(input)",
            "dist": b"literal root filename",
            "vendor.py": b"print('root-level filename is not an excluded directory')",
        },
        directories=("empty",),
    )
    by_path = {node.path: node for node in nodes}

    assert set(by_path) == {
        "dist",
        "empty",
        "src",
        "src/app.py",
        "src/readme.txt",
        "vendor",
        "vendor/lib.js",
        "vendor.py",
    }
    assert by_path["src"].has_children is True
    assert by_path["empty"].has_children is False
    assert by_path["src/app.py"].analysis_state is ScanFileState.TARGET
    assert by_path["src/app.py"].language == "Python"
    assert by_path["src/readme.txt"].analysis_state is ScanFileState.UNSUPPORTED_EXTENSION
    assert by_path["vendor/lib.js"].analysis_state is ScanFileState.EXCLUDED_DIRECTORY
    assert by_path["dist"].analysis_state is ScanFileState.UNSUPPORTED_EXTENSION
    assert by_path["vendor.py"].analysis_state is ScanFileState.TARGET
    assert by_path["vendor.py"].language == "Python"


def test_manifest_target_classification_matches_analyzer_discovery(
    tmp_path: Path,
) -> None:
    archive_data = make_zip(
        {
            "src/app.py": b"print('x')",
            "src/ui.tsx": b"export const x = 1",
            "node_modules/pkg/index.js": b"eval(input)",
            "readme.md": b"text",
        }
    )
    archive = inspect_archive(archive_data, max_entries=100, max_extracted_bytes=4096)
    from app.archive import extract_archive

    extract_archive(archive_data, archive, tmp_path)
    manifest_targets = {
        node.path
        for node in build_scan_file_manifest(archive)
        if node.analysis_state is ScanFileState.TARGET
    }
    analyzer_targets = {
        path.relative_to(tmp_path).as_posix() for path in discover_analysis_targets(tmp_path)
    }

    assert manifest_targets == analyzer_targets == {"src/app.py", "src/ui.tsx"}


def test_finding_counts_are_exact_for_files_and_directory_subtrees() -> None:
    nodes = build({"src/app.py": b"eval(x)", "src/clean.py": b"print('x')"})
    raw_results = normalize_results(
        [
            {"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"},
            {"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"},
        ],
        ["Python"],
    )
    results = [WeaknessResult.model_validate(result) for result in raw_results]

    counted = attach_finding_counts(nodes, results)
    by_path = {node.path: node for node in counted}
    summary = validate_scan_file_manifest(counted, results)

    assert by_path["src/app.py"].finding_count == 2
    assert by_path["src/clean.py"].finding_count == 0
    assert by_path["src"].finding_count == 2
    assert summary.archive_file_count == 2
    assert summary.analysis_file_count == 2
    assert summary.language_file_counts == {"Python": 2}


def test_finding_must_point_to_target_and_subtree_counts_fail_closed() -> None:
    nodes = build({"src/readme.txt": b"text", "src/app.py": b"eval(x)"})
    raw_results = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "src/readme.txt"}],
        ["Python"],
    )
    results = [WeaknessResult.model_validate(result) for result in raw_results]

    with pytest.raises(ValueError, match="TARGET file"):
        attach_finding_counts(nodes, results)

    valid_raw = normalize_results(
        [{"check_id": "kisa-2021-02-python-code-injection", "path": "src/app.py"}],
        ["Python"],
    )
    valid_results = [WeaknessResult.model_validate(result) for result in valid_raw]
    counted = list(attach_finding_counts(nodes, valid_results))
    directory_index = next(index for index, node in enumerate(counted) if node.path == "src")
    counted[directory_index] = counted[directory_index].model_copy(update={"finding_count": 0})
    with pytest.raises(ValueError, match="finding counts"):
        validate_scan_file_manifest(counted, valid_results)


def test_manifest_models_never_contain_source_or_absolute_paths() -> None:
    nodes = build({"src/app.py": b"super secret value"})
    payload = nodes[-1].model_dump(mode="json", by_alias=True)

    assert set(payload) == {
        "path",
        "parentPath",
        "name",
        "depth",
        "entryType",
        "sizeBytes",
        "language",
        "analysisState",
        "findingCount",
        "hasChildren",
    }
    assert "super secret" not in str(payload)
    assert not str(payload["path"]).startswith("/")
