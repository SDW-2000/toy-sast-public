#!/bin/sh
set -eu

temporary_dir=$(mktemp -d)
archive_file="$temporary_dir/fixtures.zip"
cookie_jar="$temporary_dir/cookies.txt"
web_origin=$(docker compose exec -T api printenv WEB_ORIGIN)
if [ -z "$web_origin" ]; then
  printf 'API WEB_ORIGIN is empty.\n' >&2
  exit 1
fi
smoke_email="smoke-$(date +%s)-$$@toy-sast.local"
smoke_password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
project_id=""
smoke_user_created=false

cleanup() {
  set +e
  if [ -n "$project_id" ] && [ -s "$cookie_jar" ]; then
    cleanup_attempt=0
    cleanup_status=""
    while [ "$cleanup_attempt" -lt 10 ]; do
      cleanup_status=$(command curl --silent --show-error --cookie "$cookie_jar" \
        -H "Origin: $web_origin" -X DELETE -o /dev/null -w '%{http_code}' \
        "http://localhost:8000/api/projects/$project_id")
      if [ "$cleanup_status" = 204 ] || [ "$cleanup_status" = 404 ]; then
        project_id=""
        break
      fi
      cleanup_attempt=$((cleanup_attempt + 1))
      sleep 1
    done
    if [ -n "$project_id" ]; then
      printf 'Smoke cleanup could not delete project %s (HTTP %s).\n' \
        "$project_id" "$cleanup_status" >&2
    fi
  fi
  if [ "$smoke_user_created" = true ]; then
    docker compose exec -T -e SMOKE_ADMIN_EMAIL="$smoke_email" api python -c \
      'import os; from app.config import get_settings; from psycopg import connect; connection = connect(get_settings().database_url); cursor = connection.cursor(); cursor.execute("DELETE FROM users WHERE email = %s", (os.environ["SMOKE_ADMIN_EMAIL"],)); connection.commit(); cursor.close(); connection.close()' \
      >/dev/null
  fi
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT

assert_json() {
  assertion_label=$1
  assertion_payload=$2
  assertion_filter=$3
  if printf '%s' "$assertion_payload" | jq -e "$assertion_filter" >/dev/null; then
    return
  fi

  printf '%s assertion failed. Response shape:\n' "$assertion_label" >&2
  printf '%s' "$assertion_payload" | jq '
    if type == "object" then {
      topLevelKeys: keys,
      scanId: (.scanId // null),
      status: (.status // null),
      total: (.total // null),
      itemCount: ((.items // []) | length),
      resultCount: ((.results // []) | length)
    } else {responseType: type} end
  ' >&2 || true
  exit 1
}

assert_empty_worker_path() {
  worker_path=$1
  volume_label=$2
  case "$worker_path" in
    /data/sources|/work) ;;
    *)
      printf 'Refusing to inspect unexpected worker path: %s\n' "$worker_path" >&2
      exit 1
      ;;
  esac

  if ! entry_count=$(docker compose exec -T worker-analyzer sh -c \
    "find $worker_path -mindepth 1 -print | wc -l"); then
    printf 'Could not inspect %s.\n' "$volume_label" >&2
    exit 1
  fi
  entry_count=$(printf '%s' "$entry_count" | tr -d '[:space:]')
  case "$entry_count" in
    ''|*[!0-9]*)
      printf '%s returned a non-numeric entry count.\n' "$volume_label" >&2
      exit 1
      ;;
  esac
  if [ "$entry_count" -ne 0 ]; then
    printf '%s retained %s filesystem entries after scan completion.\n' \
      "$volume_label" "$entry_count" >&2
    exit 1
  fi
}

curl --fail --silent --show-error http://localhost:8000/health >/dev/null
curl --fail --silent --show-error http://localhost:8000/ready >/dev/null
curl --fail --silent --show-error http://localhost:3000 >/dev/null

printf '%s\n' "$smoke_password" | docker compose exec -T \
  -e SMOKE_ADMIN_EMAIL="$smoke_email" \
  api python -c \
  'import os, sys; from uuid import uuid4; from app.auth import hash_password; from app.config import get_settings; from app.database import Database; from app.schemas import UserRole; password = sys.stdin.readline().rstrip("\n"); Database(get_settings().database_url).create_user(str(uuid4()), email=os.environ["SMOKE_ADMIN_EMAIL"], password_hash=hash_password(password), role=UserRole.ADMIN)'
smoke_user_created=true

login_payload=$(jq -nc \
  --arg email "$smoke_email" \
  --arg password "$smoke_password" \
  '{email: $email, password: $password}')
command curl --fail --silent --show-error \
  --cookie-jar "$cookie_jar" \
  -H "Origin: $web_origin" \
  -H 'Content-Type: application/json' \
  -d "$login_payload" \
  http://localhost:8000/api/auth/login >/dev/null

curl() {
  command curl --cookie "$cookie_jar" -H "Origin: $web_origin" "$@"
}

python3 -m zipfile -c "$archive_file" analyzer/fixtures

rejected_project_name="Rejected Smoke $smoke_email"
rejected_payload=$(jq -nc \
  --arg name "$rejected_project_name" \
  '{name: $name, description: "must roll back", memberUserIds: ["00000000-0000-4000-8000-000000000000"]}')
rejected_status=$(curl --silent --show-error -o "$temporary_dir/rejected.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' -d "$rejected_payload" \
  http://localhost:8000/api/projects)
if [ "$rejected_status" != 422 ]; then
  printf 'Invalid project assignment returned HTTP %s instead of 422.\n' "$rejected_status" >&2
  exit 1
fi
rejected_list=$(curl --fail --silent --show-error --get \
  --data-urlencode "query=$rejected_project_name" \
  http://localhost:8000/api/projects)
assert_json 'Rejected project transaction rollback' "$rejected_list" '.total == 0'

project_payload=$(curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  -d '{"name":"Integration Smoke","description":"Automated local smoke project"}' \
  http://localhost:8000/api/projects)
project_id=$(printf '%s' "$project_payload" | jq -er '.id')
export TOY_SAST_SMOKE_PROJECT_ID="$project_id"

created_payload=$(curl --fail --silent --show-error \
  -F "projectId=$project_id" \
  -F "source=@$archive_file" \
  http://localhost:8000/api/scans)
scan_id=$(printf '%s' "$created_payload" | jq -er '.scanId')
export TOY_SAST_SMOKE_SCAN_ID="$scan_id"

scan_status=""
scan_payload=""
attempt=0
while [ "$attempt" -lt 60 ]; do
  scan_payload=$(curl --fail --silent --show-error "http://localhost:8000/api/scans/$scan_id")
  scan_status=$(printf '%s' "$scan_payload" | jq -er '.status')

  case "$scan_status" in
    COMPLETED)
      break
      ;;
    FAILED)
      printf '%s\n' "$scan_payload" | jq . >&2
      exit 1
      ;;
  esac

  attempt=$((attempt + 1))
  sleep 1
done

if [ "$scan_status" != "COMPLETED" ]; then
  printf 'Scan did not complete within 60 seconds. Last response:\n' >&2
  printf '%s\n' "$scan_payload" | jq . >&2
  exit 1
fi

assert_json 'Completed scan snapshot' "$scan_payload" \
  '.progressPercent == 100
  and .completedUnits == .totalUnits
  and .archiveName == "fixtures.zip"
  and .archiveFileCount >= .analysisFileCount
  and (.languageFileCounts | add) == .analysisFileCount
  and .engineSnapshot.engineName == "Semgrep"
  and .engineSnapshot.engineVersion == "1.174.0"
  and .engineSnapshot.registeredRuleCount == 86
  and .engineSnapshot.executedRuleCount == 79'

detected_language_count=$(printf '%s' "$scan_payload" | jq -er '.detectedLanguages | length')
export TOY_SAST_SMOKE_DETECTED_LANGUAGE_COUNT="$detected_language_count"

project_detail_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/projects/$project_id")
assert_json 'Persistent project detail' "$project_detail_payload" '
  .id == env.TOY_SAST_SMOKE_PROJECT_ID
  and .latestScan.scanId == env.TOY_SAST_SMOKE_SCAN_ID
  and .latestScan.status == "COMPLETED"
'

project_scans_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/projects/$project_id/scans?limit=100&offset=0")
assert_json 'Persistent project scan history' "$project_scans_payload" '
  .total >= 1
  and any(.items[];
    .scanId == env.TOY_SAST_SMOKE_SCAN_ID
    and .projectId == env.TOY_SAST_SMOKE_PROJECT_ID
    and .status == "COMPLETED")
'

files_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/scans/$scan_id/files?limit=200")
assert_json 'Metadata-only file manifest' "$files_payload" '
  .scanId == env.TOY_SAST_SMOKE_SCAN_ID
  and .manifestAvailable == true
  and .manifestVersion == 1
  and .unavailableReason == null
  and .parentPath == null
  and ((keys - [
    "items", "manifestAvailable", "manifestVersion", "nextCursor",
    "parentPath", "scanId", "unavailableReason"
  ]) | length) == 0
  and (.items | length) > 0
  and ((.nextCursor == null) or ((.nextCursor | type) == "string"))
  and (all(.items[];
    ((keys - [
      "analysisState", "depth", "entryType", "findingCount", "hasChildren",
      "language", "name", "parentPath", "path", "sizeBytes"
    ]) | length) == 0
    and (.path | type) == "string"
    and (.path | startswith("/") | not)
    and (.path | contains("\\") | not)
    and (.path | test("(^|/)\\.\\.($|/)") | not)
    and .parentPath == null
    and .name == (.path | split("/")[-1])
    and .depth == 1
    and (.findingCount >= 0)
    and ((.hasChildren | type) == "boolean")
    and (
      if .entryType == "DIRECTORY" then
        .analysisState == "DIRECTORY" and .sizeBytes == null and .language == null
      elif .entryType == "FILE" then
        .analysisState != "DIRECTORY" and .sizeBytes >= 0
      else false end
    )
  ))
'

issues_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/scans/$scan_id/issues?limit=200")
assert_json 'Unfiltered global issue model' "$issues_payload" '
  .scanId == env.TOY_SAST_SMOKE_SCAN_ID
  and .issueModelAvailable == true
  and .unavailableReason == null
  and .stats != null
  and .total >= 1
  and (.items | length) == .total
  and .nextCursor == null
  and .stats.totalIssueCount == .total
  and .stats.detectedIssueCount == .stats.totalIssueCount
  and ((.stats | keys | sort) == ["detectedIssueCount", "severityCounts", "totalIssueCount"])
  and ((.stats.severityCounts | keys | sort) == ["ERROR", "INFO", "WARNING"])
  and ([.stats.severityCounts.ERROR, .stats.severityCounts.WARNING,
        .stats.severityCounts.INFO] | add) == .stats.totalIssueCount
  and (all(.items[];
    ((keys - [
      "confidence", "detectionBasisVersion", "detectionRationale", "endColumn", "endLine",
      "findingKind", "fingerprint", "fingerprintVersion", "implementationStatus",
      "issueId", "language", "message", "path", "resultStatus", "ruleId", "severity",
      "startColumn", "startLine", "weaknessId", "weaknessName", "weaknessNumber"
    ]) | length) == 0
    and (.issueId | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
    and (.fingerprint | test("^[0-9a-f]{64}$"))
    and .fingerprintVersion == 1
    and .detectionBasisVersion == 1
    and .resultStatus == "DETECTED"
    and .findingKind == "DETECTED"
    and .confidence == "MEDIUM"
    and .confidence != "HIGH"
    and (.detectionRationale | type) == "string"
    and ((.detectionRationale | length) >= 1 and (.detectionRationale | length) <= 4000)
    and (. as $issue | (.detectionRationale | contains($issue.ruleId)))
    and (.severity == "ERROR" or .severity == "WARNING" or .severity == "INFO")
    and (.path | startswith("/") | not)
    and (.path | test("(^|/)\\.\\.($|/)") | not)
    and .startLine >= 1 and .startColumn >= 1
  ))
  and ([.. | objects | keys[]
    | select(test("^(source|snippet|content|code|sourceCode|sourceSnippet|raw|rawResult|metavars|metavariables)$"; "i"))]
    | length) == 0
'

TOY_SAST_SMOKE_GLOBAL_STATS=$(printf '%s' "$issues_payload" | jq -c '.stats')
export TOY_SAST_SMOKE_GLOBAL_STATS

filtered_issues_payload=$(curl --fail --silent --show-error --get \
  --data-urlencode 'status=DETECTED' \
  --data-urlencode 'limit=1' \
  "http://localhost:8000/api/scans/$scan_id/issues")
assert_json 'Filtered issue page and cursor' "$filtered_issues_payload" '
  .issueModelAvailable == true
  and .stats == (env.TOY_SAST_SMOKE_GLOBAL_STATS | fromjson)
  and .total > 1
  and (.items | length) == 1
  and .items[0].resultStatus == "DETECTED"
  and .items[0].findingKind == "DETECTED"
  and .items[0].detectionBasisVersion == 1
  and .items[0].confidence == "MEDIUM"
  and ((.nextCursor | type) == "string")
  and (.nextCursor | length) > 0
'

first_issue_id=$(printf '%s' "$filtered_issues_payload" | jq -er '.items[0].issueId')
first_issue_fingerprint=$(printf '%s' "$filtered_issues_payload" | jq -er '.items[0].fingerprint')
first_issue_path=$(printf '%s' "$filtered_issues_payload" | jq -er '.items[0].path')
issues_cursor=$(printf '%s' "$filtered_issues_payload" | jq -er '.nextCursor')
export TOY_SAST_SMOKE_FIRST_ISSUE_ID="$first_issue_id"
export TOY_SAST_SMOKE_FIRST_FINGERPRINT="$first_issue_fingerprint"
export TOY_SAST_SMOKE_FIRST_PATH="$first_issue_path"

issue_directory=$(printf '%s' "$files_payload" | jq -er '
  first(.items[] | select(.entryType == "DIRECTORY" and .findingCount > 0) | .path)
')
export TOY_SAST_SMOKE_ISSUE_DIRECTORY="$issue_directory"

directory_issues_payload=$(curl --fail --silent --show-error --get \
  --data-urlencode "path=$issue_directory" \
  --data-urlencode 'pathScope=DIRECTORY' \
  --data-urlencode 'status=DETECTED' \
  --data-urlencode 'limit=200' \
  "http://localhost:8000/api/scans/$scan_id/issues")
assert_json 'Directory issue scope' "$directory_issues_payload" '
  .issueModelAvailable == true
  and .stats == (env.TOY_SAST_SMOKE_GLOBAL_STATS | fromjson)
  and .total >= 1
  and (.items | length) >= 1
  and (all(.items[];
    .resultStatus == "DETECTED"
    and (.path | startswith(env.TOY_SAST_SMOKE_ISSUE_DIRECTORY + "/"))
  ))
'

file_issues_payload=$(curl --fail --silent --show-error --get \
  --data-urlencode "path=$first_issue_path" \
  --data-urlencode 'pathScope=FILE' \
  --data-urlencode 'status=DETECTED' \
  --data-urlencode 'limit=200' \
  "http://localhost:8000/api/scans/$scan_id/issues")
assert_json 'Exact file issue scope' "$file_issues_payload" '
  .issueModelAvailable == true
  and .stats == (env.TOY_SAST_SMOKE_GLOBAL_STATS | fromjson)
  and .total >= 1
  and (.items | length) >= 1
  and (all(.items[];
    .resultStatus == "DETECTED"
    and .path == env.TOY_SAST_SMOKE_FIRST_PATH
  ))
'

cursor_issues_payload=$(curl --fail --silent --show-error --get \
  --data-urlencode 'status=DETECTED' \
  --data-urlencode 'limit=1' \
  --data-urlencode "cursor=$issues_cursor" \
  "http://localhost:8000/api/scans/$scan_id/issues")
assert_json 'Opaque issue cursor continuation' "$cursor_issues_payload" '
  .issueModelAvailable == true
  and .stats == (env.TOY_SAST_SMOKE_GLOBAL_STATS | fromjson)
  and (.items | length) == 1
  and .items[0].resultStatus == "DETECTED"
  and .items[0].issueId != env.TOY_SAST_SMOKE_FIRST_ISSUE_ID
  and ((.nextCursor == null) or ((.nextCursor | type) == "string"))
'

issue_detail_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/scans/$scan_id/issues/$first_issue_id")
assert_json 'Immutable issue detail without source retention' "$issue_detail_payload" '
  .scanId == env.TOY_SAST_SMOKE_SCAN_ID
  and .issueId == env.TOY_SAST_SMOKE_FIRST_ISSUE_ID
  and .fingerprint == env.TOY_SAST_SMOKE_FIRST_FINGERPRINT
  and (.fingerprint | test("^[0-9a-f]{64}$"))
  and .fingerprintVersion == 1
  and .resultStatus == "DETECTED"
  and .findingKind == "DETECTED"
  and .detectionBasisVersion == 1
  and .confidence == "MEDIUM"
  and .confidence != "HIGH"
  and (.detectionRationale | type) == "string"
  and ((.detectionRationale | length) >= 1 and (.detectionRationale | length) <= 4000)
  and (. as $detail | ($detail.detectionRationale | contains($detail.rule.ruleId)))
  and (.weakness.weaknessId | length) > 0
  and (.weakness.number >= 1 and .weakness.number <= 49)
  and (.weakness.name | length) > 0
  and (.weakness.description | length) > 0
  and (.weakness.sastClassification | length) > 0
  and (.rule.ruleId | length) > 0
  and (.rule.language | length) > 0
  and (.rule.message | length) > 0
  and (.rule.severity == "ERROR" or .rule.severity == "WARNING" or .rule.severity == "INFO")
  and .location.path == env.TOY_SAST_SMOKE_FIRST_PATH
  and .location.startLine >= 1 and .location.startColumn >= 1
  and ((.location.endLine > .location.startLine)
    or (.location.endLine == .location.startLine
      and .location.endColumn >= .location.startColumn))
  and .engineSnapshot.engineName == "Semgrep"
  and .engineSnapshot.registeredRuleCount == 86
  and .engineSnapshot.executedRuleCount == 79
  and .evidence.available == false
  and .evidence.reason == "SOURCE_NOT_RETAINED"
  and (.automationLimitation | type) == "string"
  and ((.automationLimitation | length) >= 1 and (.automationLimitation | length) <= 4000)
  and (.automationLimitation | contains("위험 패턴"))
  and (.automationLimitation | contains("자동으로 확인하지 않습니다"))
  and (.manualVerificationChecks | type) == "array"
  and ((.manualVerificationChecks | length) >= 1
    and (.manualVerificationChecks | length) <= 5)
  and all(.manualVerificationChecks[];
    type == "string" and length >= 1 and length <= 1000)
  and (.remediation | type) == "string"
  and ((.remediation | length) >= 1 and (.remediation | length) <= 4000)
  and (.safeImplementationExample | type) == "string"
  and ((.safeImplementationExample | length) >= 1
    and (.safeImplementationExample | length) <= 4000)
  and (.safeImplementationExample | contains("개념 예시(원본 코드 아님)"))
  and (.references | type) == "array"
  and ((.references | length) >= 1 and (.references | length) <= 3)
  and all(.references[];
    type == "string"
    and length >= 1 and length <= 1000
    and test("^https://cwe\\.mitre\\.org/data/(definitions/[1-9][0-9]{0,5}\\.html|index\\.html)$"))
  and ((.rule.cweId == null
      and .references == ["https://cwe.mitre.org/data/index.html"])
    or ((.rule.cweId | test("^CWE-[1-9][0-9]{0,5}$"))
      and .references == [
        "https://cwe.mitre.org/data/definitions/"
        + (.rule.cweId | ltrimstr("CWE-"))
        + ".html"
      ]))
  and ([.. | objects | keys[]
    | select(test("^(source|snippet|content|code|sourceCode|sourceSnippet|raw|rawResult|metavars|metavariables)$"; "i"))]
    | length) == 0
'

coverage_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/scans/$scan_id/coverage")
assert_json 'V2 KISA 49 coverage with language rows and global issue stats' "$coverage_payload" '
  .scanId == env.TOY_SAST_SMOKE_SCAN_ID
  and .coverageModelVersion == 2
  and .totalWeaknessCount == 49
  and (.items | length) == 49
  and ([.items[].weaknessId] | unique | length) == 49
  and ([.items[].number] | unique | length) == 49
  and .summary.totalCriterionCount == 49
  and ((.summary | keys | sort) == ["checkFailedCriterionCount", "detectedCriterionCount",
    "issueStats", "notDetectedCriterionCount", "notSupportedCriterionCount",
    "totalCriterionCount", "totalFindingCount", "totalLanguageResultCount"])
  and (.summary.detectedCriterionCount + .summary.notDetectedCriterionCount
    + .summary.notSupportedCriterionCount + .summary.checkFailedCriterionCount) == 49
  and .summary.totalLanguageResultCount == (49 * (env.TOY_SAST_SMOKE_DETECTED_LANGUAGE_COUNT | tonumber))
  and .summary.issueStats == (env.TOY_SAST_SMOKE_GLOBAL_STATS | fromjson)
  and .summary.totalFindingCount == .summary.issueStats.totalIssueCount
  and (all(.items[];
    .findingCount >= 0
    and (.languages | length) == (env.TOY_SAST_SMOKE_DETECTED_LANGUAGE_COUNT | tonumber)
    and .findingCount == ([.languages[].findingCount] | add)
    and (all(.languages[];
      ((.supportStatus == "SUPPORTED"
        and .executedRuleCount >= 1
        and (.resultStatus == "DETECTED"
          or .resultStatus == "NOT_DETECTED"
          or .resultStatus == "CHECK_FAILED")
        and ((.resultStatus == "DETECTED" and .findingCount >= 1)
          or ((.resultStatus == "NOT_DETECTED" or .resultStatus == "CHECK_FAILED")
            and .findingCount == 0)))
      or (.supportStatus == "NOT_SUPPORTED"
        and .resultStatus == "NOT_SUPPORTED"
        and .executedRuleCount == 0
        and .findingCount == 0))
    ))
  ))
'

results_payload=$(curl --fail --silent --show-error \
  "http://localhost:8000/api/scans/$scan_id/results")
assert_json 'V2-compatible 49-result summary without review findings' "$results_payload" '
  .status == "COMPLETED"
  and .totalWeaknessCount == 49
  and (.results | length) == 49
  and ([.results[].weaknessId] | unique | length) == 49
  and .results[0].weaknessId == "KISA-2021-01"
  and .results[-1].weaknessId == "KISA-2021-49"
  and (.detectedLanguages | sort) == ["Java", "JavaScript", "Python"]
  and .supportedRuleCount == 79
  and (all(.results[];
    (.supportStatus == "SUPPORTED" or .supportStatus == "NOT_SUPPORTED")
    and (.resultStatus == "DETECTED" or .resultStatus == "NOT_DETECTED"
      or .resultStatus == "NOT_SUPPORTED")
    and .resultStatus != "REVIEW_REQUIRED"
  ))
  and ([.results[].findings[]] | length) >= 1
  and (all(.results[].findings[];
    (.kind == "DETECTED" or .kind == null)
    and .kind != "REVIEW_SIGNAL"
  ))
'

assert_empty_worker_path /data/sources 'source_data volume'
assert_empty_worker_path /work 'workspace_data volume'

printf 'TOY SAST web, API, worker, analyzer, persistence, issue, and retention smoke checks passed.\n'
