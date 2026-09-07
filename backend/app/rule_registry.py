import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

RULEPACK_VERSION = "kisa-2021-v2"
RULEPACK_DIRECTORY = "kisa-2021"
RULEPACK_FILES = (
    "java.yml",
    "javascript.yml",
    "manual-review-signals.yml",
    "python.yml",
    "remaining-automatic.yml",
    "remaining-input-validation.yml",
)
RULESET_DIGEST = "3a726e8ed591b2c8f1455726f6a2c740487dab61e666f891216279136eedf81a"
_MANUAL_REVIEW_WEAKNESS_NUMBERS = frozenset({16, 18, 19, 26, 33, 41, 44})
_MAX_RULE_MESSAGE_LENGTH = 4000
_RULE_ID_LINE_PATTERN = re.compile(r"^  - id: (?P<rule_id>[a-z0-9-]+)\s*$")
_RULE_MESSAGE_LINE_PATTERN = re.compile(r"^    message:(?P<message>.*)$")
_SEMGREP_METAVARIABLE_PATTERN = re.compile(
    r"\$(?:\.\.\.)?(?=[A-Z0-9_]*[A-Z_])[A-Z0-9_]+(?![A-Z0-9_])"
)


class FindingKind(StrEnum):
    DETECTED = "DETECTED"
    REVIEW_SIGNAL = "REVIEW_SIGNAL"


class RulepackIntegrityError(RuntimeError):
    """Raised when packaged Semgrep rules do not match the registered rulepack."""


@dataclass(frozen=True)
class RuleRegistration:
    weakness_number: int
    language: str
    finding_kind: FindingKind


@dataclass(frozen=True)
class RulepackManifest:
    version: str
    digest: str
    rule_ids: frozenset[str]
    language_counts: Mapping[str, int]


_RULE_IDS = (
    "kisa-2021-02-java-code-injection",
    "kisa-2021-02-javascript-code-injection",
    "kisa-2021-02-python-code-injection",
    "kisa-2021-05-java-os-command-injection",
    "kisa-2021-05-javascript-os-command-injection",
    "kisa-2021-05-python-os-command-injection",
    "kisa-2021-08-java-xxe-enabled",
    "kisa-2021-08-javascript-xxe-enabled",
    "kisa-2021-08-python-unsafe-xml-parser",
    "kisa-2021-12-java-ssrf-dynamic-url",
    "kisa-2021-12-javascript-ssrf-dynamic-url",
    "kisa-2021-12-python-ssrf-dynamic-url",
    "kisa-2021-20-java-world-accessible-permission",
    "kisa-2021-20-javascript-world-writable-permission",
    "kisa-2021-20-python-world-writable-permission",
    "kisa-2021-21-java-weak-crypto",
    "kisa-2021-21-javascript-weak-crypto",
    "kisa-2021-21-python-weak-crypto",
    "kisa-2021-23-java-hardcoded-secret",
    "kisa-2021-23-javascript-hardcoded-secret",
    "kisa-2021-23-python-hardcoded-secret",
    "kisa-2021-24-java-short-rsa-key",
    "kisa-2021-24-javascript-short-rsa-key",
    "kisa-2021-24-python-short-rsa-key",
    "kisa-2021-25-java-insecure-random-security-value",
    "kisa-2021-25-javascript-insecure-random-security-value",
    "kisa-2021-25-python-insecure-random-security-value",
    "kisa-2021-28-java-trust-all-hostnames",
    "kisa-2021-28-javascript-tls-verification-disabled",
    "kisa-2021-28-python-tls-verification-disabled",
    "kisa-2021-29-java-insecure-cookie",
    "kisa-2021-29-javascript-insecure-cookie",
    "kisa-2021-29-python-insecure-cookie",
    "kisa-2021-30-java-secret-in-comment",
    "kisa-2021-30-javascript-secret-in-comment",
    "kisa-2021-30-python-secret-in-comment",
    "kisa-2021-31-java-unsalted-password-hash",
    "kisa-2021-31-javascript-unsalted-password-hash",
    "kisa-2021-31-python-unsalted-password-hash",
    "kisa-2021-35-java-unconditional-loop",
    "kisa-2021-35-javascript-unconditional-loop",
    "kisa-2021-35-python-unconditional-loop",
    "kisa-2021-36-java-error-detail-exposure",
    "kisa-2021-36-javascript-error-detail-exposure",
    "kisa-2021-36-python-error-detail-exposure",
    "kisa-2021-37-java-empty-catch",
    "kisa-2021-37-javascript-empty-catch",
    "kisa-2021-37-python-empty-except",
    "kisa-2021-38-java-overly-broad-catch",
    "kisa-2021-38-python-overly-broad-except",
    "kisa-2021-43-java-unsafe-deserialization",
    "kisa-2021-43-javascript-unsafe-deserialization",
    "kisa-2021-43-python-unsafe-deserialization",
    "kisa-2021-45-java-leftover-debug-code",
    "kisa-2021-45-javascript-leftover-debug-code",
    "kisa-2021-45-python-leftover-debug-code",
)

_EXPANDED_RULE_IDS = (
    "kisa-2021-01-python-sql-injection",
    "kisa-2021-03-java-path-traversal",
    "kisa-2021-04-javascript-xss",
    "kisa-2021-06-java-unsafe-upload-filename",
    "kisa-2021-07-javascript-open-redirect",
    "kisa-2021-09-java-xpath-injection",
    "kisa-2021-10-python-ldap-injection",
    "kisa-2021-11-java-csrf-disabled",
    "kisa-2021-13-python-http-response-splitting",
    "kisa-2021-14-java-untrusted-allocation-size",
    "kisa-2021-15-javascript-untrusted-auth-decision",
    "kisa-2021-16-java-native-memory-boundary",
    "kisa-2021-17-java-format-string-injection",
    "kisa-2021-18-javascript-unprotected-sensitive-route",
    "kisa-2021-19-python-object-access-without-ownership-check",
    "kisa-2021-22-python-plaintext-sensitive-data",
    "kisa-2021-26-javascript-weak-password-policy",
    "kisa-2021-27-javascript-ignored-signature-verification",
    "kisa-2021-32-python-download-and-execute",
    "kisa-2021-33-python-login-without-rate-limit",
    "kisa-2021-34-java-toctou-file-check",
    "kisa-2021-39-java-null-dereference",
    "kisa-2021-40-python-unclosed-resource",
    "kisa-2021-41-java-use-after-close",
    "kisa-2021-42-javascript-uninitialized-variable",
    "kisa-2021-44-java-static-session-storage",
    "kisa-2021-46-java-private-array-return",
    "kisa-2021-47-java-public-array-assignment",
    "kisa-2021-48-java-dns-security-decision",
    "kisa-2021-49-java-dangerous-api",
)

_LANGUAGE_NAMES = {
    "java": "Java",
    "javascript": "JavaScript",
    "python": "Python",
}


def _registration(rule_id: str) -> RuleRegistration:
    parts = rule_id.split("-", 4)
    if len(parts) != 5 or parts[:2] != ["kisa", "2021"] or not parts[4]:
        raise RuntimeError(f"invalid registered rule id: {rule_id}")
    try:
        weakness_number = int(parts[2])
        language = _LANGUAGE_NAMES[parts[3]]
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"invalid registered rule id: {rule_id}") from exc
    finding_kind = (
        FindingKind.REVIEW_SIGNAL
        if weakness_number in _MANUAL_REVIEW_WEAKNESS_NUMBERS
        else FindingKind.DETECTED
    )
    return RuleRegistration(
        weakness_number=weakness_number,
        language=language,
        finding_kind=finding_kind,
    )


RULE_REGISTRY = MappingProxyType(
    {rule_id: _registration(rule_id) for rule_id in (*_RULE_IDS, *_EXPANDED_RULE_IDS)}
)

# REVIEW_SIGNAL rules are retained in the immutable rulepack so historical v1
# snapshots can still be validated.  None currently satisfy the v2 contract's
# stronger claim that a code-only match is a deterministic vulnerability.  In
# particular, their own messages require policy, middleware, native code, alias,
# or runtime context that the rule cannot observe.  New v2 support is therefore
# derived only from DETECTED registrations.
REVIEW_SIGNAL_AUDIT = MappingProxyType(
    {
        rule_id: "코드 패턴만으로 취약 조건을 확정할 수 없어 v2 자동 탐지에서 제외"
        for rule_id, registration in RULE_REGISTRY.items()
        if registration.finding_kind is FindingKind.REVIEW_SIGNAL
    }
)
VERIFIED_DETECTED_RULE_REGISTRY = MappingProxyType(
    {
        rule_id: registration
        for rule_id, registration in RULE_REGISTRY.items()
        if registration.finding_kind is FindingKind.DETECTED
    }
)

if len(RULE_REGISTRY) != 86:
    raise RuntimeError("the KISA 2021 rule registry must contain exactly 86 rule IDs")

if {item.weakness_number for item in RULE_REGISTRY.values()} != set(range(1, 50)):
    raise RuntimeError("the KISA 2021 rule registry must cover all 49 weaknesses")


def _language_support(
    registry: Mapping[str, RuleRegistration] = RULE_REGISTRY,
) -> dict[int, frozenset[str]]:
    mutable: dict[int, set[str]] = {}
    for registration in registry.values():
        mutable.setdefault(registration.weakness_number, set()).add(registration.language)
    return {number: frozenset(languages) for number, languages in mutable.items()}


RULE_LANGUAGE_SUPPORT = MappingProxyType(_language_support())
VERIFIED_RULE_LANGUAGE_SUPPORT = MappingProxyType(
    _language_support(VERIFIED_DETECTED_RULE_REGISTRY)
)
SUPPORTED_LANGUAGES = tuple(_LANGUAGE_NAMES.values())
VERIFIED_RULE_SUPPORT_MATRIX = MappingProxyType(
    {
        (weakness_number, language): frozenset(
            rule_id
            for rule_id, registration in VERIFIED_DETECTED_RULE_REGISTRY.items()
            if registration.weakness_number == weakness_number
            and registration.language == language
        )
        for weakness_number in range(1, 50)
        for language in SUPPORTED_LANGUAGES
    }
)

if len(REVIEW_SIGNAL_AUDIT) != 7:
    raise RuntimeError("all seven REVIEW_SIGNAL rules must have an explicit v2 audit decision")
if len(VERIFIED_RULE_SUPPORT_MATRIX) != 147:
    raise RuntimeError("the verified support matrix must contain 49 x 3 combinations")


def _validate_rule_messages(filename: str, rule_file_text: str) -> frozenset[str]:
    rule_messages: dict[str, str] = {}
    current_rule_id: str | None = None
    for line in rule_file_text.splitlines():
        rule_id_match = _RULE_ID_LINE_PATTERN.fullmatch(line)
        if rule_id_match is not None:
            current_rule_id = rule_id_match.group("rule_id")
            if current_rule_id in rule_messages:
                raise RulepackIntegrityError(
                    f"KISA 2021 룰 메시지가 중복되었습니다: {current_rule_id}"
                )
            continue

        message_match = _RULE_MESSAGE_LINE_PATTERN.fullmatch(line)
        if message_match is None:
            continue
        if current_rule_id is None or current_rule_id in rule_messages:
            raise RulepackIntegrityError(
                f"KISA 2021 룰 메시지 구성이 올바르지 않습니다: {filename}"
            )

        message = message_match.group("message").strip()
        if (
            not message
            or len(message) > _MAX_RULE_MESSAGE_LENGTH
            or message.startswith(("#", "'", '"', "|", ">", "!", "&", "*", "[", "{"))
        ):
            raise RulepackIntegrityError(
                "KISA 2021 룰 메시지는 비어 있지 않은 4000자 이하의 "
                f"단일 행 문자열이어야 합니다: {current_rule_id}"
            )
        if _SEMGREP_METAVARIABLE_PATTERN.search(message) is not None:
            raise RulepackIntegrityError(
                f"KISA 2021 룰 메시지에는 Semgrep 메타변수를 포함할 수 없습니다: {current_rule_id}"
            )
        rule_messages[current_rule_id] = message

    return frozenset(rule_messages)


def validate_rulepack_manifest(rules_root: Path) -> RulepackManifest:
    rules_directory = rules_root / RULEPACK_DIRECTORY
    try:
        actual_rule_files = tuple(
            sorted(
                path.relative_to(rules_directory).as_posix()
                for path in rules_directory.rglob("*")
                if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
            )
        )
    except OSError as exc:
        raise RulepackIntegrityError("KISA 2021 룰팩 파일을 읽지 못했습니다.") from exc
    if actual_rule_files != RULEPACK_FILES:
        raise RulepackIntegrityError("KISA 2021 룰팩 파일 구성이 등록된 v2 계약과 다릅니다.")

    digest = hashlib.sha256()
    message_rule_ids: set[str] = set()
    try:
        for filename in RULEPACK_FILES:
            rule_file = rules_directory / filename
            if rule_file.is_symlink() or not rule_file.is_file():
                raise RulepackIntegrityError(
                    "KISA 2021 룰팩에는 일반 YAML 파일만 포함할 수 있습니다."
                )
            digest.update(filename.encode("utf-8"))
            digest.update(b"\0")
            rule_file_bytes = rule_file.read_bytes()
            digest.update(rule_file_bytes)
            digest.update(b"\0")
            try:
                rule_file_text = rule_file_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RulepackIntegrityError(
                    f"KISA 2021 룰팩 YAML은 UTF-8이어야 합니다: {filename}"
                ) from exc
            file_rule_ids = _validate_rule_messages(filename, rule_file_text)
            duplicate_rule_ids = message_rule_ids & file_rule_ids
            if duplicate_rule_ids:
                raise RulepackIntegrityError(
                    f"KISA 2021 룰 메시지가 파일 간 중복되었습니다: {sorted(duplicate_rule_ids)}"
                )
            message_rule_ids.update(file_rule_ids)
    except OSError as exc:
        raise RulepackIntegrityError("KISA 2021 룰팩 파일을 읽지 못했습니다.") from exc
    if message_rule_ids != set(RULE_REGISTRY):
        raise RulepackIntegrityError(
            "KISA 2021 룰 메시지 구성이 등록된 86개 룰과 일치하지 않습니다."
        )
    actual_digest = digest.hexdigest()
    if actual_digest != RULESET_DIGEST:
        raise RulepackIntegrityError("KISA 2021 룰팩 내용이 등록된 v2 계약과 다릅니다.")

    language_counts = {
        language: sum(registration.language == language for registration in RULE_REGISTRY.values())
        for language in _LANGUAGE_NAMES.values()
    }
    return RulepackManifest(
        version=RULEPACK_VERSION,
        digest=actual_digest,
        rule_ids=frozenset(RULE_REGISTRY),
        language_counts=MappingProxyType(language_counts),
    )
