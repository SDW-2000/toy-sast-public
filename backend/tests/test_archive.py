import stat
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

from app.archive import UnsafeArchiveError, extract_archive, inspect_archive


def make_zip(entries: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def test_inspect_and_extract_safe_archive(tmp_path: Path) -> None:
    archive_data = make_zip({"src/main.py": b"print('safe')"})
    manifest = inspect_archive(archive_data, max_entries=10, max_extracted_bytes=1024)

    extracted = extract_archive(archive_data, manifest, tmp_path)

    assert len(manifest.entries) == 1
    assert manifest.total_uncompressed_bytes == 13
    assert extracted == [tmp_path / "src" / "main.py"]
    assert extracted[0].read_bytes() == b"print('safe')"


@pytest.mark.parametrize(
    "name",
    [
        "../escape.py",
        "/absolute.py",
        "C:\\escape.py",
        "C:escape.py",
        "\\absolute.py",
        "\\\\server\\share.py",
        "src\\..\\escape.py",
        "src\\\\escape.py",
        "src/./app.py",
        "src//app.py",
        "bad\nname.py",
    ],
)
def test_rejects_archive_paths_outside_workspace(name: str) -> None:
    with pytest.raises(UnsafeArchiveError):
        inspect_archive(make_zip({name: b"x"}), max_entries=10, max_extracted_bytes=1024)


def test_normalizes_windows_archive_separators_before_extract(tmp_path: Path) -> None:
    archive_data = make_zip({"src\\main.py": b"print('windows')"})
    manifest = inspect_archive(archive_data, max_entries=10, max_extracted_bytes=1024)

    extracted = extract_archive(archive_data, manifest, tmp_path)

    assert manifest.files[0].path == "src/main.py"
    assert extracted == [tmp_path / "src" / "main.py"]
    assert extracted[0].read_bytes() == b"print('windows')"


def test_accepts_windows_directory_entries(tmp_path: Path) -> None:
    output = BytesIO()
    directory = ZipInfo("src\\")
    directory.create_system = 0
    directory.external_attr = 0x10
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr(directory, b"")
        archive.writestr("src\\app.py", b"print('windows')")

    manifest = inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)
    extracted = extract_archive(output.getvalue(), manifest, tmp_path)

    assert manifest.entries[0].path == "src"
    assert manifest.entries[0].is_directory is True
    assert extracted == [tmp_path / "src" / "app.py"]


def test_rejects_windows_directory_entry_with_file_content() -> None:
    output = BytesIO()
    directory = ZipInfo("src\\")
    directory.create_system = 0
    directory.external_attr = 0x10
    with ZipFile(output, "w") as archive:
        archive.writestr(directory, b"hidden")
        archive.writestr("app.py", b"print('safe')")

    with pytest.raises(UnsafeArchiveError, match="파일 내용"):
        inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)


def test_rejects_mixed_separator_duplicate_paths() -> None:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("src/app.py", b"first")
        archive.writestr("src\\app.py", b"second")

    with pytest.raises(UnsafeArchiveError, match="중복 경로"):
        inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)


def test_rejects_invalid_zip_data() -> None:
    with pytest.raises(UnsafeArchiveError, match="ZIP"):
        inspect_archive(b"not-a-zip", max_entries=10, max_extracted_bytes=1024)


def test_rejects_archive_over_entry_limit() -> None:
    archive_data = make_zip({"one.py": b"1", "two.py": b"2"})

    with pytest.raises(UnsafeArchiveError, match="항목 수"):
        inspect_archive(archive_data, max_entries=1, max_extracted_bytes=1024)


def test_rejects_archive_over_extracted_size_limit() -> None:
    archive_data = make_zip({"large.py": b"12345"})

    with pytest.raises(UnsafeArchiveError, match="압축 해제 크기"):
        inspect_archive(archive_data, max_entries=10, max_extracted_bytes=4)


def test_rejects_duplicate_archive_paths() -> None:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("duplicate.py", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("duplicate.py", b"second")

    with pytest.raises(UnsafeArchiveError, match="중복 경로"):
        inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)


def test_rejects_symbolic_link_entry() -> None:
    output = BytesIO()
    link = ZipInfo("source-link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(output, "w") as archive:
        archive.writestr(link, "source.py")

    with pytest.raises(UnsafeArchiveError, match="심볼릭 링크"):
        inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)


def test_rejects_special_file_disguised_as_directory() -> None:
    output = BytesIO()
    special_entry = ZipInfo("device/")
    special_entry.create_system = 3
    special_entry.external_attr = (stat.S_IFCHR | 0o755) << 16
    with ZipFile(output, "w") as archive:
        archive.writestr(special_entry, b"")
        archive.writestr("app.py", b"print('safe')")

    with pytest.raises(UnsafeArchiveError, match="일반 디렉터리"):
        inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)


def test_rejects_file_parent_prefix_collision() -> None:
    archive_data = make_zip({"src": b"file", "src/app.py": b"print('x')"})

    with pytest.raises(UnsafeArchiveError, match="파일과 하위 항목 충돌"):
        inspect_archive(archive_data, max_entries=10, max_extracted_bytes=1024)


def test_rejects_unicode_normalized_duplicate_paths() -> None:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("caf\N{LATIN SMALL LETTER E WITH ACUTE}.py", b"one")
        archive.writestr("cafe\N{COMBINING ACUTE ACCENT}.py", b"two")

    with pytest.raises(UnsafeArchiveError, match="중복 경로"):
        inspect_archive(output.getvalue(), max_entries=10, max_extracted_bytes=1024)


def test_rejects_excessive_path_depth_and_segment_bytes() -> None:
    deep_path = "/".join(["d"] * 64 + ["app.py"])
    long_segment = f"{'x' * 256}.py"

    with pytest.raises(UnsafeArchiveError, match="깊이"):
        inspect_archive(make_zip({deep_path: b"x"}), max_entries=10, max_extracted_bytes=1024)
    with pytest.raises(UnsafeArchiveError, match="조각 길이"):
        inspect_archive(make_zip({long_segment: b"x"}), max_entries=10, max_extracted_bytes=1024)


def test_rejects_manifest_node_expansion_above_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.archive.MAX_MANIFEST_NODES", 1)

    with pytest.raises(UnsafeArchiveError, match="정규화된 항목 수"):
        inspect_archive(make_zip({"src/app.py": b"x"}), max_entries=10, max_extracted_bytes=1024)
