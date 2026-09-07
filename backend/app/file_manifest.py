from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from app.analyzer import EXCLUDED_DIRECTORY_NAMES, identify_language
from app.archive import (
    MAX_ARCHIVE_DEPTH,
    MAX_MANIFEST_NODES,
    ArchiveManifest,
    UnsafeArchiveError,
    normalize_archive_path,
)
from app.schemas import (
    NormalizedIssue,
    ScanFileNode,
    ScanFileState,
    ScanFileType,
    WeaknessResult,
)

MANIFEST_VERSION = 1


@dataclass(frozen=True)
class ManifestSummary:
    node_count: int
    archive_file_count: int
    analysis_file_count: int
    detected_languages: tuple[str, ...]
    language_file_counts: dict[str, int]


def build_scan_file_manifest(manifest: ArchiveManifest) -> tuple[ScanFileNode, ...]:
    directories: set[str] = set()
    files: dict[str, ScanFileNode] = {}
    for member in manifest.entries:
        directories.update(_parent_paths(member.path))
        if member.is_directory:
            directories.add(member.path)
            continue
        parts = PurePosixPath(member.path).parts
        detected_language = identify_language(Path(member.path))
        if set(parts[:-1]) & EXCLUDED_DIRECTORY_NAMES:
            state = ScanFileState.EXCLUDED_DIRECTORY
            language = None
        elif detected_language is None:
            state = ScanFileState.UNSUPPORTED_EXTENSION
            language = None
        else:
            state = ScanFileState.TARGET
            language = detected_language
        files[member.path] = ScanFileNode(
            path=member.path,
            parent_path=_parent_path(member.path),
            name=parts[-1],
            depth=len(parts),
            entry_type=ScanFileType.FILE,
            size_bytes=member.info.file_size,
            language=language,
            analysis_state=state,
            finding_count=0,
            has_children=False,
        )

    parents_with_children = {
        parent for path in directories | set(files) if (parent := _parent_path(path)) is not None
    }
    nodes = [
        ScanFileNode(
            path=path,
            parent_path=_parent_path(path),
            name=PurePosixPath(path).name,
            depth=len(PurePosixPath(path).parts),
            entry_type=ScanFileType.DIRECTORY,
            size_bytes=None,
            language=None,
            analysis_state=ScanFileState.DIRECTORY,
            finding_count=0,
            has_children=path in parents_with_children,
        )
        for path in directories
    ]
    nodes.extend(files.values())
    if len(nodes) > MAX_MANIFEST_NODES:
        raise UnsafeArchiveError("ZIP 파일의 정규화된 항목 수가 허용 범위를 초과합니다.")
    return tuple(sorted(nodes, key=lambda node: node.path.encode("utf-8")))


def attach_finding_counts(
    nodes: Sequence[ScanFileNode], results: Sequence[WeaknessResult]
) -> tuple[ScanFileNode, ...]:
    return attach_issue_counts(
        nodes,
        [finding.path for result in results for finding in result.findings],
    )


def attach_issue_counts(
    nodes: Sequence[ScanFileNode], issues: Sequence[NormalizedIssue] | Sequence[str]
) -> tuple[ScanFileNode, ...]:
    node_by_path = {node.path: node for node in nodes}
    if len(node_by_path) != len(nodes):
        raise ValueError("manifest paths must be unique")
    file_counts: Counter[str] = Counter()
    directory_counts: Counter[str] = Counter()
    paths = [issue if isinstance(issue, str) else issue.path for issue in issues]
    for path in paths:
        target = node_by_path.get(path)
        if (
            target is None
            or target.entry_type is not ScanFileType.FILE
            or target.analysis_state is not ScanFileState.TARGET
        ):
            raise ValueError("every finding path must point to a TARGET file")
        file_counts[path] += 1
        for parent in _parent_paths(path):
            directory_counts[parent] += 1
    counted = tuple(
        node.model_copy(
            update={
                "finding_count": (
                    directory_counts[node.path]
                    if node.entry_type is ScanFileType.DIRECTORY
                    else file_counts[node.path]
                )
            }
        )
        for node in nodes
    )
    validate_scan_file_manifest(counted, finding_paths=paths)
    return counted


def validate_scan_file_manifest(
    nodes: Sequence[ScanFileNode],
    results: Sequence[WeaknessResult] = (),
    *,
    finding_paths: Sequence[str] | None = None,
) -> ManifestSummary:
    if not nodes or len(nodes) > MAX_MANIFEST_NODES:
        raise ValueError("manifest node count is outside the allowed range")
    node_by_path = {node.path: node for node in nodes}
    if len(node_by_path) != len(nodes):
        raise ValueError("manifest paths must be unique")

    parents_with_children = {node.parent_path for node in nodes if node.parent_path is not None}
    for node in nodes:
        validate_scan_file_node_structure(node)
        expected_parent = _parent_path(node.path)
        if expected_parent is not None:
            parent = node_by_path.get(expected_parent)
            if parent is None or parent.entry_type is not ScanFileType.DIRECTORY:
                raise ValueError("manifest parent must be an existing directory")

        if node.entry_type is ScanFileType.DIRECTORY:
            if node.has_children != (node.path in parents_with_children):
                raise ValueError("directory has_children is inconsistent")

    expected_file_counts: Counter[str] = Counter()
    expected_directory_counts: Counter[str] = Counter()
    if finding_paths is not None and results:
        raise ValueError("provide results or finding_paths, not both")
    paths = (
        list(finding_paths)
        if finding_paths is not None
        else [finding.path for result in results for finding in result.findings]
    )
    for path in paths:
        target = node_by_path.get(path)
        if (
            target is None
            or target.entry_type is not ScanFileType.FILE
            or target.analysis_state is not ScanFileState.TARGET
        ):
            raise ValueError("every finding path must point to a TARGET file")
        expected_file_counts[path] += 1
        for parent_path in _parent_paths(path):
            expected_directory_counts[parent_path] += 1
    for node in nodes:
        expected = (
            expected_directory_counts[node.path]
            if node.entry_type is ScanFileType.DIRECTORY
            else expected_file_counts[node.path]
        )
        if node.finding_count != expected:
            raise ValueError("manifest finding counts do not match normalized findings")

    files = [node for node in nodes if node.entry_type is ScanFileType.FILE]
    targets = [node for node in files if node.analysis_state is ScanFileState.TARGET]
    if any(node.language is None for node in targets):
        raise ValueError("TARGET files must have a detected language")
    typed_language_counts = dict(
        sorted(Counter(node.language for node in targets if node.language is not None).items())
    )
    return ManifestSummary(
        node_count=len(nodes),
        archive_file_count=len(files),
        analysis_file_count=len(targets),
        detected_languages=tuple(typed_language_counts),
        language_file_counts=typed_language_counts,
    )


def validate_scan_file_node_structure(node: ScanFileNode) -> None:
    try:
        normalized = normalize_archive_path(node.path)
    except UnsafeArchiveError as exc:
        raise ValueError("manifest path is not a safe normalized relative path") from exc
    if normalized != node.path:
        raise ValueError("manifest path is not normalized")
    parts = PurePosixPath(node.path).parts
    expected_parent = _parent_path(node.path)
    if node.parent_path != expected_parent or node.depth != len(parts):
        raise ValueError("manifest parent or depth is inconsistent")
    if node.depth > MAX_ARCHIVE_DEPTH:
        raise ValueError("manifest depth exceeds the allowed limit")
    if node.entry_type is ScanFileType.DIRECTORY:
        return

    expected_language = identify_language(Path(node.path))
    if set(parts[:-1]) & EXCLUDED_DIRECTORY_NAMES:
        expected_state = ScanFileState.EXCLUDED_DIRECTORY
        expected_language = None
    elif expected_language is None:
        expected_state = ScanFileState.UNSUPPORTED_EXTENSION
    else:
        expected_state = ScanFileState.TARGET
    if (
        node.analysis_state is not expected_state
        or node.language != expected_language
        or node.has_children
    ):
        raise ValueError("manifest file classification is inconsistent")


def _parent_path(path: str) -> str | None:
    parts = PurePosixPath(path).parts
    return "/".join(parts[:-1]) or None


def _parent_paths(path: str) -> tuple[str, ...]:
    parts = PurePosixPath(path).parts
    return tuple("/".join(parts[:index]) for index in range(1, len(parts)))
