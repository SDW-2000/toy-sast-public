from importlib.metadata import PackageNotFoundError

import pytest

from app.engine import ENGINE_VERSION, EngineIntegrityError, validate_engine_version


def test_validate_engine_version_accepts_pinned_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.engine.version", lambda _package: ENGINE_VERSION)

    assert validate_engine_version() == ENGINE_VERSION


def test_validate_engine_version_rejects_missing_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_package(_package: str) -> str:
        raise PackageNotFoundError("semgrep")

    monkeypatch.setattr("app.engine.version", missing_package)

    with pytest.raises(EngineIntegrityError, match="패키지를 찾지 못했습니다"):
        validate_engine_version()


def test_validate_engine_version_rejects_unpinned_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.engine.version", lambda _package: "0.0.0")

    with pytest.raises(EngineIntegrityError, match="버전이 고정 계약"):
        validate_engine_version()
