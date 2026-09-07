import hashlib
import shutil
from pathlib import Path

import pytest

import app.rule_registry as rule_registry
from app.rule_registry import (
    REVIEW_SIGNAL_AUDIT,
    RULE_REGISTRY,
    VERIFIED_RULE_SUPPORT_MATRIX,
    FindingKind,
    RulepackIntegrityError,
    validate_rulepack_manifest,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGED_RULES_ROOT = PROJECT_ROOT / "analyzer" / "rules"


def _copy_rulepack(tmp_path: Path) -> tuple[Path, Path]:
    copied_rules_root = tmp_path / "rules"
    copied_rulepack = copied_rules_root / "kisa-2021"
    shutil.copytree(PACKAGED_RULES_ROOT / "kisa-2021", copied_rulepack)
    return copied_rules_root, copied_rulepack


def _replace_first_message(rule_file: Path, replacement: str) -> None:
    original = rule_file.read_text(encoding="utf-8")
    lines = original.splitlines()
    message_index = next(
        index for index, line in enumerate(lines) if line.startswith("    message:")
    )
    lines[message_index] = f"    message: {replacement}"
    rule_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _rulepack_digest(rulepack: Path) -> str:
    digest = hashlib.sha256()
    for filename in rule_registry.RULEPACK_FILES:
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update((rulepack / filename).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def test_registered_rulepack_accepts_all_86_source_free_messages() -> None:
    manifest = validate_rulepack_manifest(PACKAGED_RULES_ROOT)

    assert manifest.rule_ids == frozenset(RULE_REGISTRY)
    assert len(manifest.rule_ids) == 86


def test_v2_support_matrix_is_complete_and_review_audit_is_explicit() -> None:
    assert len(VERIFIED_RULE_SUPPORT_MATRIX) == 147
    assert set(REVIEW_SIGNAL_AUDIT) == {
        rule_id
        for rule_id, registration in RULE_REGISTRY.items()
        if registration.finding_kind is FindingKind.REVIEW_SIGNAL
    }
    assert len(REVIEW_SIGNAL_AUDIT) == 7
    assert all(
        RULE_REGISTRY[rule_id].finding_kind is FindingKind.DETECTED
        for rule_ids in VERIFIED_RULE_SUPPORT_MATRIX.values()
        for rule_id in rule_ids
    )


@pytest.mark.parametrize(
    "metavariable",
    ["$FOO", "$...ARGS", "$_", "$1FOO", "$FOObar"],
)
def test_rulepack_rejects_semgrep_metavariable_in_message(
    tmp_path: Path,
    metavariable: str,
) -> None:
    copied_rules_root, copied_rulepack = _copy_rulepack(tmp_path)
    _replace_first_message(
        copied_rulepack / "java.yml",
        f"탐지된 소스 조각 {metavariable}을 메시지에 포함하지 마세요.",
    )

    with pytest.raises(RulepackIntegrityError, match="Semgrep 메타변수"):
        validate_rulepack_manifest(copied_rules_root)


def test_rulepack_allows_currency_and_lowercase_literal_dollars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied_rules_root, copied_rulepack = _copy_rulepack(tmp_path)
    _replace_first_message(
        copied_rulepack / "java.yml",
        "가격 $100과 리터럴 $value는 Semgrep 메타변수가 아닙니다.",
    )
    monkeypatch.setattr(rule_registry, "RULESET_DIGEST", _rulepack_digest(copied_rulepack))

    manifest = validate_rulepack_manifest(copied_rules_root)

    assert len(manifest.rule_ids) == 86


@pytest.mark.parametrize("message", ["", "가" * 4001])
def test_rulepack_rejects_empty_or_oversized_message(
    tmp_path: Path,
    message: str,
) -> None:
    copied_rules_root, copied_rulepack = _copy_rulepack(tmp_path)
    _replace_first_message(copied_rulepack / "java.yml", message)

    with pytest.raises(RulepackIntegrityError, match="4000자 이하"):
        validate_rulepack_manifest(copied_rules_root)
