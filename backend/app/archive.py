import shutil
import stat
import unicodedata
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath
from zipfile import BadZipFile, ZipFile, ZipInfo

MAX_ARCHIVE_DEPTH = 64
MAX_ARCHIVE_PATH_BYTES = 4096
MAX_ARCHIVE_SEGMENT_BYTES = 255
MAX_MANIFEST_NODES = 20_000


class UnsafeArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class ArchiveMember:
    info: ZipInfo
    path: str
    is_directory: bool


@dataclass(frozen=True)
class ArchiveManifest:
    entries: tuple[ArchiveMember, ...]
    files: tuple[ArchiveMember, ...]
    total_uncompressed_bytes: int


def inspect_archive(
    archive_data: bytes, *, max_entries: int, max_extracted_bytes: int
) -> ArchiveManifest:
    try:
        with ZipFile(BytesIO(archive_data)) as archive:
            raw_entries = tuple(archive.infolist())
    except BadZipFile as exc:
        raise UnsafeArchiveError("유효한 ZIP 파일이 아닙니다.") from exc
    if not raw_entries:
        raise UnsafeArchiveError("ZIP 파일이 비어 있습니다.")
    if len(raw_entries) > max_entries:
        raise UnsafeArchiveError("ZIP 파일의 항목 수가 허용 범위를 초과합니다.")

    entries: list[ArchiveMember] = []
    files: list[ArchiveMember] = []
    seen_paths: set[str] = set()
    file_paths: set[str] = set()
    all_directories: set[str] = set()
    total_uncompressed_bytes = 0
    for entry in raw_entries:
        is_directory = entry.is_dir() or entry.filename.endswith("\\")
        normalized = normalize_archive_path(entry.filename, is_directory=is_directory)
        if normalized in seen_paths:
            raise UnsafeArchiveError("ZIP 파일에 정규화 후 중복 경로가 있습니다.")
        seen_paths.add(normalized)
        unix_mode = entry.external_attr >> 16
        if stat.S_ISLNK(unix_mode):
            raise UnsafeArchiveError("심볼릭 링크가 포함된 ZIP 파일은 허용하지 않습니다.")
        member = ArchiveMember(info=entry, path=normalized, is_directory=is_directory)
        entries.append(member)
        file_type = stat.S_IFMT(unix_mode)
        if is_directory:
            if entry.file_size != 0:
                raise UnsafeArchiveError("ZIP 디렉터리 항목에는 파일 내용이 없어야 합니다.")
            if file_type not in (0, stat.S_IFDIR):
                raise UnsafeArchiveError("일반 디렉터리가 아닌 ZIP 항목은 허용하지 않습니다.")
            all_directories.add(normalized)
            continue
        if file_type not in (0, stat.S_IFREG):
            raise UnsafeArchiveError("일반 파일이 아닌 ZIP 항목은 허용하지 않습니다.")
        total_uncompressed_bytes += entry.file_size
        if total_uncompressed_bytes > max_extracted_bytes:
            raise UnsafeArchiveError("ZIP 압축 해제 크기가 허용 범위를 초과합니다.")
        file_paths.add(normalized)
        files.append(member)
    if not files:
        raise UnsafeArchiveError("ZIP 파일에 분석할 파일이 없습니다.")
    for path in seen_paths:
        parents = _parent_paths(path)
        if file_paths.intersection(parents):
            raise UnsafeArchiveError("ZIP 파일 경로에 파일과 하위 항목 충돌이 있습니다.")
        all_directories.update(parents)
    if len(files) + len(all_directories) > MAX_MANIFEST_NODES:
        raise UnsafeArchiveError("ZIP 파일의 정규화된 항목 수가 허용 범위를 초과합니다.")
    return ArchiveManifest(tuple(entries), tuple(files), total_uncompressed_bytes)


def extract_archive(
    archive_data: bytes, manifest: ArchiveManifest, destination: Path
) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    extracted: list[Path] = []
    with ZipFile(BytesIO(archive_data)) as archive:
        for member in manifest.files:
            target = destination.joinpath(*PurePosixPath(member.path).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            resolved = target.resolve()
            if not resolved.is_relative_to(destination_root):
                raise UnsafeArchiveError("ZIP 경로가 작업공간을 벗어납니다.")
            with archive.open(member.info, "r") as source, resolved.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            extracted.append(resolved)
    return extracted


def normalize_archive_path(filename: str, *, is_directory: bool = False) -> str:
    if not filename or any(_is_control(character) for character in filename):
        raise UnsafeArchiveError("잘못된 ZIP 항목 경로입니다.")
    windows_path = PureWindowsPath(filename)
    if windows_path.is_absolute() or windows_path.drive:
        raise UnsafeArchiveError("절대경로가 포함된 ZIP 파일은 허용하지 않습니다.")
    canonical_path = filename.replace("\\", "/")
    if canonical_path.startswith("/"):
        raise UnsafeArchiveError("절대경로가 포함된 ZIP 파일은 허용하지 않습니다.")

    raw_path = (
        canonical_path[:-1] if is_directory and canonical_path.endswith("/") else canonical_path
    )
    if not raw_path:
        raise UnsafeArchiveError("잘못된 ZIP 항목 경로입니다.")
    raw_segments = raw_path.split("/")
    if any(segment in {"", ".", ".."} for segment in raw_segments):
        raise UnsafeArchiveError("빈 경로 또는 점 경로가 포함된 ZIP 파일은 허용하지 않습니다.")

    segments = tuple(unicodedata.normalize("NFC", segment) for segment in raw_segments)
    if any(segment in {"", ".", ".."} for segment in segments):
        raise UnsafeArchiveError("정규화 후 잘못된 ZIP 항목 경로입니다.")
    if len(segments) > MAX_ARCHIVE_DEPTH:
        raise UnsafeArchiveError("ZIP 항목 경로 깊이가 허용 범위를 초과합니다.")
    if any(len(segment.encode("utf-8")) > MAX_ARCHIVE_SEGMENT_BYTES for segment in segments):
        raise UnsafeArchiveError("ZIP 항목 경로 조각 길이가 허용 범위를 초과합니다.")
    normalized = "/".join(segments)
    if len(normalized.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES:
        raise UnsafeArchiveError("ZIP 항목 경로 길이가 허용 범위를 초과합니다.")
    posix_path = PurePosixPath(normalized)
    if posix_path.is_absolute() or posix_path.as_posix() != normalized:
        raise UnsafeArchiveError("잘못된 ZIP 항목 경로입니다.")
    return normalized


def _parent_paths(path: str) -> tuple[str, ...]:
    parts = PurePosixPath(path).parts
    return tuple("/".join(parts[:index]) for index in range(1, len(parts)))


def _is_control(character: str) -> bool:
    return unicodedata.category(character) == "Cc"
