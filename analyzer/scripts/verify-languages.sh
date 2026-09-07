#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
analyzer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
rules_root="$analyzer_root/rules/kisa-2021"
vulnerable_result=$(mktemp)
safe_result=$(mktemp)
suppression_result=$(mktemp)
exclusion_result=$(mktemp)
exclusion_root=$(mktemp -d)
trap 'rm -f "$vulnerable_result" "$safe_result" "$suppression_result" "$exclusion_result"; rm -rf "$exclusion_root"' EXIT

run_semgrep() {
  semgrep scan \
    --disable-version-check \
    --metrics=off \
    --disable-nosem \
    --no-git-ignore \
    --x-ignore-semgrepignore-files \
    --no-rewrite-rule-ids \
    --strict \
    --max-target-bytes=0 \
    --timeout=0 \
    --timeout-threshold=0 \
    --exclude '**/.cache/**' \
    --exclude '**/.git/**' \
    --exclude '**/.mypy_cache/**' \
    --exclude '**/.next/**' \
    --exclude '**/.nox/**' \
    --exclude '**/.nuxt/**' \
    --exclude '**/.pytest_cache/**' \
    --exclude '**/.ruff_cache/**' \
    --exclude '**/.tox/**' \
    --exclude '**/.venv/**' \
    --exclude '**/__pycache__/**' \
    --exclude '**/build/**' \
    --exclude '**/dist/**' \
    --exclude '**/node_modules/**' \
    --exclude '**/target/**' \
    --exclude '**/vendor/**' \
    --exclude '**/venv/**' \
    --config "$rules_root" \
    --json \
    "$@"
}

run_semgrep \
  "$analyzer_root/fixtures/java/Vulnerable.java" \
  "$analyzer_root/fixtures/javascript/vulnerable.js" \
  "$analyzer_root/fixtures/python/vulnerable.py" \
  "$analyzer_root/fixtures/remaining/input-validation/Vulnerable.java" \
  "$analyzer_root/fixtures/remaining/input-validation/vulnerable.js" \
  "$analyzer_root/fixtures/remaining/input-validation/vulnerable.py" \
  "$analyzer_root/fixtures/remaining/automatic/Vulnerable.java" \
  "$analyzer_root/fixtures/remaining/automatic/vulnerable.js" \
  "$analyzer_root/fixtures/remaining/automatic/vulnerable.py" \
  "$analyzer_root/fixtures/remaining/manual/Vulnerable.java" \
  "$analyzer_root/fixtures/remaining/manual/vulnerable.js" \
  "$analyzer_root/fixtures/remaining/manual/vulnerable.py" > "$vulnerable_result"

run_semgrep \
  "$analyzer_root/fixtures/java/Safe.java" \
  "$analyzer_root/fixtures/javascript/safe.js" \
  "$analyzer_root/fixtures/python/safe.py" \
  "$analyzer_root/fixtures/remaining/input-validation/Safe.java" \
  "$analyzer_root/fixtures/remaining/input-validation/safe.js" \
  "$analyzer_root/fixtures/remaining/input-validation/safe.py" \
  "$analyzer_root/fixtures/remaining/automatic/Safe.java" \
  "$analyzer_root/fixtures/remaining/automatic/safe.js" \
  "$analyzer_root/fixtures/remaining/automatic/safe.py" \
  "$analyzer_root/fixtures/remaining/manual/Safe.java" \
  "$analyzer_root/fixtures/remaining/manual/safe.js" \
  "$analyzer_root/fixtures/remaining/manual/safe.py" > "$safe_result"

run_semgrep \
  "$analyzer_root/fixtures/suppression/bypass.py" > "$suppression_result"

mkdir -p "$exclusion_root/src"
printf '%s\n' 'export const safeValue = "ok";' > "$exclusion_root/src/safe.ts"
for excluded_directory in \
  .cache .git .mypy_cache .next .nox .nuxt .pytest_cache .ruff_cache .tox .venv \
  __pycache__ build dist node_modules target vendor venv
do
  mkdir -p "$exclusion_root/$excluded_directory"
  printf '%s\n' 'value = eval(user_input)' > "$exclusion_root/$excluded_directory/ignored.py"
done

run_semgrep \
  "$exclusion_root" > "$exclusion_result"

python - \
  "$rules_root" \
  "$vulnerable_result" \
  "$safe_result" \
  "$suppression_result" \
  "$exclusion_result" \
  "$analyzer_root/fixtures" \
  "$exclusion_root" <<'PY'
from collections import Counter
import json
from pathlib import Path
import re
import sys

import yaml
from app.analyzer import normalize_language_results, normalize_results, supported_rule_count
from app.catalog import ImplementationStatus, KISA_CATALOG
from app.rule_registry import RULEPACK_VERSION, RULE_REGISTRY, validate_rulepack_manifest

expected = {
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
}

registered = set(RULE_REGISTRY)
if expected != registered:
    raise SystemExit(
        "verification manifest/backend registry mismatch: "
        f"missing={sorted(registered - expected)} extra={sorted(expected - registered)}"
    )

required_metadata = {
    "weakness_id",
    "category_id",
    "category_number",
    "category",
    "name",
    "description",
    "language",
    "implementation_status",
    "cwe",
}
declared: dict[str, dict[str, object]] = {}
for rule_file in sorted(Path(sys.argv[1]).glob("*.yml")):
    payload = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
    for rule in payload.get("rules", []):
        rule_id = rule["id"]
        if rule_id in declared:
            raise SystemExit(f"duplicate rule id: {rule_id}")
        declared[rule_id] = rule

if set(declared) != expected:
    raise SystemExit(
        "unexpected declared rule ids: "
        f"missing={sorted(expected - set(declared))} extra={sorted(set(declared) - expected)}"
    )

id_pattern = re.compile(r"^kisa-2021-(\d{2})-(java|javascript|python)-[a-z0-9-]+$")
semgrep_metavariable_pattern = re.compile(
    r"\$(?:\.\.\.)?(?=[A-Z0-9_]*[A-Z_])[A-Z0-9_]+(?![A-Z0-9_])"
)
catalog_by_id = {weakness.weakness_id: weakness for weakness in KISA_CATALOG}
category_ids = {
    category: index
    for index, category in enumerate(dict.fromkeys(item.category for item in KISA_CATALOG), start=1)
}
for rule_id, rule in declared.items():
    match = id_pattern.fullmatch(rule_id)
    if match is None:
        raise SystemExit(f"invalid rule id: {rule_id}")
    message = rule.get("message")
    if not isinstance(message, str) or not message.strip() or len(message) > 4000:
        raise SystemExit(f"missing rule message: {rule_id}")
    if semgrep_metavariable_pattern.search(message) is not None:
        raise SystemExit(f"Semgrep metavariable interpolation in rule message: {rule_id}")
    if rule.get("severity") not in {"ERROR", "WARNING", "INFO"}:
        raise SystemExit(f"invalid rule severity: {rule_id}")
    metadata = rule.get("metadata", {})
    missing = required_metadata - set(metadata)
    if missing:
        raise SystemExit(f"missing metadata for {rule_id}: {sorted(missing)}")
    weakness_number, language = match.groups()
    if metadata["weakness_id"] != f"KISA-2021-{weakness_number}":
        raise SystemExit(f"weakness_id does not match rule id: {rule_id}")
    weakness = catalog_by_id.get(str(metadata["weakness_id"]))
    if weakness is None:
        raise SystemExit(f"unknown weakness_id for {rule_id}: {metadata['weakness_id']}")
    expected_catalog_metadata = {
        "category_id": category_ids[weakness.category],
        "category": weakness.category,
        "category_number": weakness.category_number,
        "name": weakness.name,
        "implementation_status": weakness.implementation_status.value,
    }
    actual_catalog_metadata = {
        key: metadata[key] for key in expected_catalog_metadata
    }
    if actual_catalog_metadata != expected_catalog_metadata:
        raise SystemExit(
            f"catalog metadata mismatch for {rule_id}: "
            f"expected={expected_catalog_metadata} actual={actual_catalog_metadata}"
        )
    if metadata["language"] != language or rule.get("languages") != [language]:
        raise SystemExit(f"language does not match rule id: {rule_id}")
    registration = RULE_REGISTRY[rule_id]
    if (
        registration.weakness_number != weakness.number
        or registration.language.casefold() != language
    ):
        raise SystemExit(f"backend registry metadata mismatch for {rule_id}")

allowed_cwe = {
    1: {"CWE-89"},
    2: {"CWE-95"},
    3: {"CWE-22", "CWE-99"},
    4: {"CWE-79"},
    5: {"CWE-78"},
    6: {"CWE-434"},
    7: {"CWE-601"},
    8: {"CWE-611"},
    9: {"CWE-643", "CWE-652"},
    10: {"CWE-90"},
    11: {"CWE-352"},
    12: {"CWE-918"},
    13: {"CWE-113"},
    14: {"CWE-190"},
    15: {"CWE-807"},
    16: {"CWE-119"},
    17: {"CWE-134"},
    18: {"CWE-306"},
    19: {"CWE-285", "CWE-639"},
    20: {"CWE-732"},
    21: {"CWE-327"},
    22: {"CWE-312", "CWE-319"},
    23: {"CWE-798"},
    24: {"CWE-326"},
    25: {"CWE-330"},
    26: {"CWE-521"},
    27: {"CWE-347"},
    28: {"CWE-295"},
    29: {"CWE-539"},
    30: {"CWE-615"},
    31: {"CWE-759"},
    32: {"CWE-494"},
    33: {"CWE-307"},
    34: {"CWE-367"},
    35: {"CWE-835"},
    36: {"CWE-209"},
    37: {"CWE-390"},
    38: {"CWE-754"},
    39: {"CWE-476"},
    40: {"CWE-404"},
    41: {"CWE-416", "CWE-672"},
    42: {"CWE-457"},
    43: {"CWE-502"},
    44: {"CWE-488", "CWE-543"},
    45: {"CWE-489"},
    46: {"CWE-495"},
    47: {"CWE-496"},
    48: {"CWE-247", "CWE-350"},
    49: {"CWE-242", "CWE-246", "CWE-382", "CWE-676"},
}
for rule_id, rule in declared.items():
    weakness_number = RULE_REGISTRY[rule_id].weakness_number
    actual_cwe = str(rule["metadata"]["cwe"])
    if actual_cwe not in allowed_cwe[weakness_number]:
        raise SystemExit(
            f"unexpected CWE for {rule_id}: expected one of "
            f"{sorted(allowed_cwe[weakness_number])}, got {actual_cwe}"
        )

declared_weakness_ids = {
    str(rule["metadata"]["weakness_id"]) for rule in declared.values()
}
catalog_covered_ids = {weakness.weakness_id for weakness in KISA_CATALOG}
if declared_weakness_ids != catalog_covered_ids:
    raise SystemExit(
        "rulepack/catalog coverage mismatch: "
        f"missing={sorted(catalog_covered_ids - declared_weakness_ids)} "
        f"extra={sorted(declared_weakness_ids - catalog_covered_ids)}"
    )

with open(sys.argv[2], encoding="utf-8") as handle:
    vulnerable_payload = json.load(handle)
with open(sys.argv[3], encoding="utf-8") as handle:
    safe_payload = json.load(handle)
with open(sys.argv[4], encoding="utf-8") as handle:
    suppression_payload = json.load(handle)
with open(sys.argv[5], encoding="utf-8") as handle:
    exclusion_payload = json.load(handle)

fixtures_root = Path(sys.argv[6]).resolve()
exclusion_root = Path(sys.argv[7]).resolve()


def validate_scan_payload(
    payload: object,
    label: str,
    expected_paths: set[str],
    *,
    scan_root: Path = fixtures_root,
) -> None:
    if not isinstance(payload, dict):
        raise SystemExit(f"{label} Semgrep output is not an object")
    errors = payload.get("errors")
    if not isinstance(errors, list) or errors:
        raise SystemExit(f"{label} Semgrep errors: {errors}")
    skipped_rules = payload.get("skipped_rules", [])
    if not isinstance(skipped_rules, list) or skipped_rules:
        raise SystemExit(f"{label} Semgrep skipped rules: {skipped_rules}")
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise SystemExit(f"{label} Semgrep paths are missing")
    for skipped in (payload.get("skipped", []), paths.get("skipped", [])):
        if not isinstance(skipped, list) or skipped:
            raise SystemExit(f"{label} Semgrep skipped targets: {skipped}")
    scanned = paths.get("scanned")
    if not isinstance(scanned, list) or not all(isinstance(path, str) for path in scanned):
        raise SystemExit(f"{label} Semgrep scanned paths are invalid")
    try:
        actual_paths = {
            Path(path).resolve().relative_to(scan_root).as_posix() for path in scanned
        }
    except ValueError as exc:
        raise SystemExit(f"{label} Semgrep scanned a path outside its fixture root") from exc
    if actual_paths != expected_paths or len(scanned) != len(actual_paths):
        raise SystemExit(
            f"{label} Semgrep target mismatch: "
            f"expected={sorted(expected_paths)} actual={sorted(actual_paths)}"
        )


validate_scan_payload(
    vulnerable_payload,
    "vulnerable",
    {
        "java/Vulnerable.java",
        "javascript/vulnerable.js",
        "python/vulnerable.py",
        "remaining/input-validation/Vulnerable.java",
        "remaining/input-validation/vulnerable.js",
        "remaining/input-validation/vulnerable.py",
        "remaining/automatic/Vulnerable.java",
        "remaining/automatic/vulnerable.js",
        "remaining/automatic/vulnerable.py",
        "remaining/manual/Vulnerable.java",
        "remaining/manual/vulnerable.js",
        "remaining/manual/vulnerable.py",
    },
)
validate_scan_payload(
    suppression_payload,
    "suppression",
    {"suppression/bypass.py"},
)
suppression_results = suppression_payload.get("results", [])
suppression_ids = [item["check_id"] for item in suppression_results]
if suppression_ids != ["kisa-2021-02-python-code-injection"]:
    raise SystemExit(
        "source suppression bypass regression: "
        f"expected Python code injection finding, got {suppression_ids}"
    )
validate_scan_payload(
    safe_payload,
    "safe",
    {
        "java/Safe.java",
        "javascript/safe.js",
        "python/safe.py",
        "remaining/input-validation/Safe.java",
        "remaining/input-validation/safe.js",
        "remaining/input-validation/safe.py",
        "remaining/automatic/Safe.java",
        "remaining/automatic/safe.js",
        "remaining/automatic/safe.py",
        "remaining/manual/Safe.java",
        "remaining/manual/safe.js",
        "remaining/manual/safe.py",
    },
)
validate_scan_payload(
    exclusion_payload,
    "exclusion",
    {"src/safe.ts"},
    scan_root=exclusion_root,
)
if exclusion_payload.get("results", []):
    raise SystemExit(
        "generated/vendor exclusions produced findings: "
        f"{[item['check_id'] for item in exclusion_payload['results']]}"
    )

counts = Counter(
    item["check_id"].rsplit(".", 1)[-1]
    for item in vulnerable_payload.get("results", [])
)
if sum(counts.values()) != 86:
    raise SystemExit(f"expected exactly 86 vulnerable findings, got {sum(counts.values())}")
if set(counts) != expected:
    raise SystemExit(
        "unexpected vulnerable rule ids: "
        f"missing={sorted(expected - set(counts))} extra={sorted(set(counts) - expected)}"
    )
duplicates = {rule_id: count for rule_id, count in counts.items() if count != 1}
if duplicates:
    raise SystemExit(f"expected exactly one vulnerable finding per rule: {duplicates}")

location_manifest: dict[str, list[object]] = {}
for location_manifest_path in sorted(fixtures_root.rglob("expected-findings.json")):
    fragment = json.loads(location_manifest_path.read_text(encoding="utf-8"))
    if not isinstance(fragment, dict):
        raise SystemExit(f"finding location manifest is not an object: {location_manifest_path}")
    duplicate_ids = set(location_manifest) & set(fragment)
    if duplicate_ids:
        raise SystemExit(
            f"duplicate finding location IDs in {location_manifest_path}: "
            f"{sorted(duplicate_ids)}"
        )
    location_manifest.update(fragment)
if set(location_manifest) != expected:
    raise SystemExit(
        "finding location manifest mismatch: "
        f"missing={sorted(expected - set(location_manifest))} "
        f"extra={sorted(set(location_manifest) - expected)}"
    )
actual_locations = {
    item["check_id"]: [
        Path(item["path"]).resolve().relative_to(fixtures_root).as_posix(),
        item["start"]["line"],
    ]
    for item in vulnerable_payload.get("results", [])
}
if actual_locations != location_manifest:
    mismatches = {
        rule_id: {
            "expected": location_manifest.get(rule_id),
            "actual": actual_locations.get(rule_id),
        }
        for rule_id in sorted(expected)
        if actual_locations.get(rule_id) != location_manifest.get(rule_id)
    }
    raise SystemExit(f"finding location mismatch: {mismatches}")

safe_results = safe_payload.get("results", [])
if safe_results:
    safe_ids = [item["check_id"].rsplit(".", 1)[-1] for item in safe_results]
    raise SystemExit(f"safe fixtures produced findings: {safe_ids}")

weaknesses = {rule_id.split("-", 4)[2] for rule_id in expected}
if len(weaknesses) != 49:
    raise SystemExit(f"expected 49 covered weaknesses, got {sorted(weaknesses)}")
normalized = normalize_results(
    vulnerable_payload.get("results", []),
    ["Java", "JavaScript", "Python"],
)
if len(normalized) != 49:
    raise SystemExit(f"expected 49 normalized weaknesses, got {len(normalized)}")
normalized_statuses = {
    str(item["weakness_id"]): str(item["result_status"])
    for item in normalized
}
expected_statuses = {
    weakness.weakness_id: (
        "DETECTED"
        if weakness.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED
        else "REVIEW_REQUIRED"
        if weakness.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED
        else "NOT_SUPPORTED"
    )
    for weakness in KISA_CATALOG
}
if normalized_statuses != expected_statuses:
    raise SystemExit(
        "unexpected normalized statuses: "
        f"expected={expected_statuses} actual={normalized_statuses}"
    )
rulepack_manifest = validate_rulepack_manifest(Path(sys.argv[1]).parent)
supported_count = supported_rule_count(
    ["Java", "JavaScript", "Python"], rulepack_manifest
)
if supported_count != 79:
    raise SystemExit(
        "backend verified automatic rule count does not match the v2 contract: "
        f"expected=79 actual={supported_count}"
    )
language_results = normalize_language_results(
    vulnerable_payload.get("results", []),
    ["Java", "JavaScript", "Python"],
)
if len(language_results) != 147:
    raise SystemExit(
        f"expected 147 criterion-language results, got {len(language_results)}"
    )
if sum(item.executed_rule_count for item in language_results) != 79:
    raise SystemExit("v2 language results do not execute exactly 79 verified automatic rules")
if sum(item.finding_count for item in language_results) != 79:
    raise SystemExit("v2 language results must ignore the seven historical review signals")
if any(
    item.result_status not in {"DETECTED", "NOT_DETECTED", "NOT_SUPPORTED", "CHECK_FAILED"}
    for item in language_results
):
    raise SystemExit("v2 language results contain a legacy result status")
if RULEPACK_VERSION != "kisa-2021-v2":
    raise SystemExit(f"unexpected rulepack version: {RULEPACK_VERSION}")
print(
    "KISA 2021 Semgrep rules verified: "
    f"{len(expected)} registered rules, 79 verified automatic rules, "
    f"{len(weaknesses)} weaknesses, exact ID/path/line match, "
    "safe zero findings, suppression bypass blocked, generated/vendor exclusions enforced, "
    "complete target coverage, "
    "49 legacy statuses, 147 v2 criterion-language statuses, "
    f"rulepack {RULEPACK_VERSION}"
)
PY
