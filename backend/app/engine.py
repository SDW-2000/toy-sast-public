from importlib.metadata import PackageNotFoundError, version

ENGINE_NAME = "Semgrep"
ENGINE_VERSION = "1.174.0"
RULEPACK_NAME = "KISA 2021 SAST"


class EngineIntegrityError(RuntimeError):
    """Raised when the analyzer runtime is not the pinned engine build."""


def validate_engine_version() -> str:
    try:
        actual = version("semgrep")
    except PackageNotFoundError as exc:
        raise EngineIntegrityError("Semgrep 분석기 패키지를 찾지 못했습니다.") from exc
    if actual != ENGINE_VERSION:
        raise EngineIntegrityError(f"Semgrep 분석기 버전이 고정 계약({ENGINE_VERSION})과 다릅니다.")
    return actual
