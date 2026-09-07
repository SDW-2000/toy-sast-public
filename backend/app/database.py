import base64
import binascii
import hashlib
import hmac
import json
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from threading import Lock
from typing import Any, Literal, Protocol, cast
from uuid import UUID, uuid4

from psycopg import Connection, connect
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.analyzer import (
    issue_detection_snapshot,
    issue_fingerprint,
    issue_id_for,
    supported_rule_count,
)
from app.archive import UnsafeArchiveError, normalize_archive_path
from app.catalog import KISA_CATALOG, ImplementationStatus
from app.file_manifest import (
    MANIFEST_VERSION,
    ManifestSummary,
    validate_scan_file_manifest,
    validate_scan_file_node_structure,
)
from app.rule_registry import (
    RULE_LANGUAGE_SUPPORT,
    RULE_REGISTRY,
    RULEPACK_VERSION,
    VERIFIED_DETECTED_RULE_REGISTRY,
    VERIFIED_RULE_SUPPORT_MATRIX,
    FindingKind,
    RulepackManifest,
)
from app.schemas import (
    CANONICAL_WEAKNESS_ID_SEQUENCE,
    AuthenticatedUser,
    ClaimedScan,
    CoverageCriterionSnapshot,
    CoverageCriterionV2,
    CoverageItem,
    CoverageResult,
    CoverageSummary,
    CoverageSummaryV2,
    EngineSnapshot,
    IssueDetail,
    IssueEvidence,
    IssueList,
    IssueListItem,
    IssueLocation,
    IssuePathScope,
    IssueRuleSnapshot,
    IssueSeverity,
    IssueSeverityCounts,
    IssueStats,
    IssueStatsV2,
    IssueUnavailableReason,
    IssueWeaknessSnapshot,
    JsonObject,
    LanguageCoverageResult,
    ManifestUnavailableReason,
    NormalizedIssue,
    Project,
    ProjectCreate,
    ProjectList,
    ProjectUpdate,
    ResultStatus,
    ScanCoverage,
    ScanFileList,
    ScanFileNode,
    ScanFileType,
    ScanList,
    ScanProgress,
    ScanResults,
    UserList,
    UserRole,
    UserSummary,
    WeaknessResult,
)

EXPECTED_WEAKNESS_ID_SEQUENCE = tuple(item.weakness_id for item in KISA_CATALOG)
CATALOG_BY_ID = {item.weakness_id: item for item in KISA_CATALOG}
CANONICAL_WEAKNESS_IDS = frozenset(CANONICAL_WEAKNESS_ID_SEQUENCE)
SCHEMA_REVISION = "20260902_03"
ISSUE_MODEL_VERSION: Literal[2] = 2
SNAPSHOT_SUMMARY_VERSION = 1
ISSUE_SNAPSHOT_SUMMARY_VERSION = 2
ISSUE_GUIDANCE_VERSION = 1
CWE_ID_PATTERN = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
CWE_INDEX_URL = "https://cwe.mitre.org/data/index.html"
DETECTED_AUTOMATION_LIMITATION = (
    "정적 규칙은 표시된 위치의 위험 패턴만 식별합니다. 실제 입력 도달성, 실행 경로, "
    "주변 방어 로직의 유효성은 자동으로 확인하지 않습니다."
)
REVIEW_SIGNAL_AUTOMATION_LIMITATION = (
    "이 검토 신호는 위험 관련 코드의 존재만 식별하며 취약 여부를 자동 판정하지 않습니다. "
    "업무 정책, 권한, 실행 상태를 사람이 확인해야 합니다."
)
DETECTED_MANUAL_CHECKS = (
    "표시된 연산까지 외부 입력이 도달하는지 데이터 흐름을 확인합니다.",
    "허용 목록, 인코딩, 권한 검사 등 방어 로직이 모든 실행 경로에 적용되는지 확인합니다.",
    "안전한 입력과 공격 입력으로 수정 전후 동작을 재현합니다.",
)
REVIEW_SIGNAL_MANUAL_CHECKS = (
    "표시된 코드가 실제 보안 경계나 민감 기능에 관여하는지 확인합니다.",
    "업무 정책, 인증·인가, 자원 수명주기 조건이 모든 실행 경로에서 지켜지는지 확인합니다.",
    "정상 사용과 오용 시나리오를 수동으로 실행하여 보호 조치의 동작을 확인합니다.",
)
SAFE_EXAMPLES = {
    "Java": (
        "개념 예시(원본 코드 아님): String validated = "
        "validator.requireAllowed(untrustedInput); trustedApi.execute(validated); "
        "실제 허용 규칙과 전용 API는 업무 맥락에 맞게 정의합니다."
    ),
    "JavaScript": (
        "개념 예시(원본 코드 아님): const validated = requireAllowed(untrustedInput); "
        "await trustedApi.execute(validated); 실제 허용 규칙과 전용 API는 업무 맥락에 "
        "맞게 정의합니다."
    ),
    "Python": (
        "개념 예시(원본 코드 아님): validated = require_allowed(untrusted_input); "
        "trusted_api.execute(validated) 실제 허용 규칙과 전용 API는 업무 맥락에 맞게 "
        "정의합니다."
    ),
}


class StaleScanLeaseError(RuntimeError):
    """Raised when a worker tries to mutate a scan after losing its lease."""


class ScanSnapshotConflictError(RuntimeError):
    """Raised when a retry observes conflicting immutable scan metadata."""


class SchemaNotReadyError(RuntimeError):
    """Raised when the database has not been migrated to the application revision."""


class ProjectNotFoundError(LookupError):
    """Raised when a project-scoped write targets an unknown project."""


class ProjectHasActiveScansError(RuntimeError):
    """Raised when deleting a project that still has pending or running analysis."""


class UserEmailAlreadyExistsError(RuntimeError):
    """Raised when creating a user with an existing normalized email."""


class InvalidProjectMembersError(ValueError):
    """Raised when a project membership update contains unknown or invalid users."""


class ScanFilesNotReadyError(RuntimeError):
    """Raised when a scan has not completed and cannot expose a manifest."""


class ScanFileParentNotFoundError(LookupError):
    """Raised when the requested manifest parent is absent or is not a directory."""


class InvalidScanFilesCursorError(ValueError):
    """Raised when a lazy manifest cursor is malformed, tampered, or out of context."""


class CorruptScanManifestError(RuntimeError):
    """Raised when persisted manifest metadata fails closed."""


class ScanIssuesNotReadyError(RuntimeError):
    """Raised when issue or coverage data is requested before completion."""


class InvalidIssuesCursorError(ValueError):
    """Raised when an issue cursor is malformed, tampered, or filter-mismatched."""


class InvalidIssueFilterError(ValueError):
    """Raised when issue filters are inconsistent or unsafe."""


class CorruptScanIssueModelError(RuntimeError):
    """Raised when persisted issue/coverage data violates its immutable contract."""


class LegacyIssueModelUnavailableError(RuntimeError):
    """Raised when a legacy scan cannot provide stable issue detail."""


@dataclass(frozen=True)
class IssueFilters:
    result_status: str | None = None
    severity: str | None = None
    language: str | None = None
    weakness_id: str | None = None
    path: str | None = None
    path_scope: IssuePathScope | None = None

    def cursor_payload(self) -> dict[str, str | None]:
        return {
            "status": self.result_status,
            "severity": self.severity,
            "language": self.language,
            "weakness": self.weakness_id,
            "path": self.path,
            "scope": self.path_scope.value if self.path_scope is not None else None,
        }


@dataclass(frozen=True)
class UserCredential:
    id: str
    email: str
    password_hash: str | None
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class _IssueSnapshotSummary:
    stats: IssueStats
    counts_by_weakness: dict[str, int]


@dataclass(frozen=True)
class _ManifestSnapshotSummary:
    node_count: int
    root_count: int
    directory_count: int
    file_count: int
    finding_count: int


@dataclass(frozen=True)
class _IssueGuidanceSnapshot:
    automation_limitation: str
    manual_verification_checks: tuple[str, ...]
    remediation: str
    safe_implementation_example: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class _IssueSnapshotReader:
    model_version: Literal[1, 2]
    summary_version: Literal[1, 2]
    guidance_version: Literal[1]
    cwe_index_url: str
    cwe_definition_url_template: str

    def validate_coverage(self, results: Sequence[JsonObject]) -> list[CoverageResult]:
        return _validate_stored_coverage(results)

    def validate_issues(self, rows: Sequence[dict[str, Any]]) -> list[NormalizedIssue]:
        issues = _validate_stored_issues(rows)
        if self.model_version == 2 and any(
            issue.finding_kind is not FindingKind.DETECTED
            or issue.result_status is not ResultStatus.DETECTED
            for issue in issues
        ):
            raise ValueError("issue model v2 stores DETECTED issues only")
        return issues

    def validate_summary(self, scan: dict[str, Any]) -> _IssueSnapshotSummary:
        return _issue_snapshot_summary_from_scan(
            scan,
            issue_model_version=self.model_version,
            summary_version=self.summary_version,
        )

    def list_item(self, row: dict[str, Any]) -> IssueListItem:
        if self.model_version == 2:
            self.validate_issues([row])
        return _issue_list_item_from_row(row)

    def detail(self, row: dict[str, Any], *, engine_snapshot: EngineSnapshot) -> IssueDetail:
        if self.model_version == 2:
            self.validate_issues([row])
        return _issue_detail_from_row(
            row,
            engine_snapshot=engine_snapshot,
            guidance_version=self.guidance_version,
            cwe_index_url=self.cwe_index_url,
            cwe_definition_url_template=self.cwe_definition_url_template,
        )


ISSUE_SNAPSHOT_READER_V1 = _IssueSnapshotReader(
    model_version=1,
    summary_version=1,
    guidance_version=1,
    cwe_index_url="https://cwe.mitre.org/data/index.html",
    cwe_definition_url_template="https://cwe.mitre.org/data/definitions/{number}.html",
)
ISSUE_SNAPSHOT_READER_V2 = _IssueSnapshotReader(
    model_version=2,
    summary_version=2,
    guidance_version=1,
    cwe_index_url="https://cwe.mitre.org/data/index.html",
    cwe_definition_url_template="https://cwe.mitre.org/data/definitions/{number}.html",
)


def _issue_snapshot_reader(model_version: object) -> _IssueSnapshotReader:
    if type(model_version) is int:
        if model_version == ISSUE_SNAPSHOT_READER_V1.model_version:
            return ISSUE_SNAPSHOT_READER_V1
        if model_version == ISSUE_SNAPSHOT_READER_V2.model_version:
            return ISSUE_SNAPSHOT_READER_V2
    raise CorruptScanIssueModelError("unsupported issue model version")


class ScanRepository(Protocol):
    def create_project(self, project: ProjectCreate) -> Project: ...

    def list_projects(
        self,
        *,
        query: str | None,
        language: str | None,
        limit: int,
        offset: int,
        member_user_id: str | None = None,
    ) -> ProjectList: ...

    def get_project(self, project_id: str) -> Project | None: ...

    def update_project(self, project_id: str, project: ProjectUpdate) -> Project | None: ...

    def delete_project(self, project_id: str) -> bool: ...

    def list_project_scans(self, project_id: str, *, limit: int, offset: int) -> ScanList: ...

    def create_scan(
        self, scan_id: str, project_id: str, archive_name: str, archive_data: bytes
    ) -> ScanProgress: ...

    def get_scan(self, scan_id: str) -> ScanProgress | None: ...

    def get_results(self, scan_id: str) -> ScanResults | None: ...

    def get_scan_files(
        self,
        scan_id: str,
        *,
        parent_path: str | None,
        limit: int,
        cursor: str | None,
    ) -> ScanFileList | None: ...

    def get_scan_issues(
        self,
        scan_id: str,
        *,
        filters: IssueFilters,
        limit: int,
        cursor: str | None,
    ) -> IssueList | None: ...

    def get_scan_issue(self, scan_id: str, issue_id: str) -> IssueDetail | None: ...

    def get_scan_coverage(self, scan_id: str) -> ScanCoverage | None: ...

    def is_scan_workspace_reapable(self, scan_id: str) -> bool: ...


class Database:
    def __init__(self, database_url: str, *, cursor_secret: str | None = None) -> None:
        self.database_url = database_url
        self._cursor_secret = (cursor_secret or database_url).encode("utf-8")
        self._schema_ready = False
        self._schema_lock = Lock()

    def _connect(self) -> Connection[dict[str, Any]]:
        return connect(self.database_url, row_factory=dict_row)

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT to_regclass('public.alembic_version')")
                    table_row = cursor.fetchone()
                    if table_row is None or table_row["to_regclass"] is None:
                        raise SchemaNotReadyError("database migrations have not been applied")
                    cursor.execute("SELECT version_num FROM alembic_version")
                    row = cursor.fetchone()
                    if row is None or row["version_num"] != SCHEMA_REVISION:
                        raise SchemaNotReadyError(f"database revision must be {SCHEMA_REVISION}")
            self._schema_ready = True

    def create_user(
        self,
        user_id: str,
        *,
        email: str,
        password_hash: str,
        role: UserRole,
    ) -> UserSummary:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (id, email, password_hash, role)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (email) DO NOTHING
                    RETURNING id::text, email, role, is_active, created_at, updated_at
                    """,
                    (user_id, email, password_hash, role.value),
                )
                row = cursor.fetchone()
        if row is None:
            raise UserEmailAlreadyExistsError(email)
        return _user_summary_from_row(row)

    def get_user_credentials_by_email(self, email: str) -> UserCredential | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id::text, email, password_hash, role, is_active,
                           created_at, updated_at
                    FROM users WHERE email = %s
                    """,
                    (email,),
                )
                row = cursor.fetchone()
        return _user_credential_from_row(row) if row else None

    def list_users(self) -> UserList:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id::text, email, role, is_active,
                           password_hash IS NULL AS invitation_pending,
                           created_at, updated_at
                    FROM users ORDER BY created_at, id
                    """
                )
                rows = cursor.fetchall()
        return UserList(items=[_user_summary_from_row(row) for row in rows])

    def set_user_active(self, user_id: str, is_active: bool) -> UserSummary | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users SET is_active = %s, updated_at = now()
                    WHERE id = %s AND role = 'USER' AND password_hash IS NOT NULL
                    RETURNING id::text, email, role, is_active, false AS invitation_pending,
                              created_at, updated_at
                    """,
                    (is_active, user_id),
                )
                row = cursor.fetchone()
                if row is not None and not is_active:
                    cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
        return _user_summary_from_row(row) if row else None

    def save_user_invitation(
        self,
        user_id: str,
        *,
        email: str,
        token_hash: str,
        expires_at: datetime,
    ) -> UserSummary:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id::text, password_hash FROM users WHERE email = %s FOR UPDATE",
                    (email,),
                )
                existing = cursor.fetchone()
                if existing is not None and existing["password_hash"] is not None:
                    raise UserEmailAlreadyExistsError(email)
                if existing is None:
                    cursor.execute(
                        """
                        INSERT INTO users (id, email, password_hash, role, is_active)
                        VALUES (%s, %s, NULL, 'USER', false)
                        RETURNING id::text
                        """,
                        (user_id, email),
                    )
                    inserted = cursor.fetchone()
                    if inserted is None:
                        raise RuntimeError("invited user was not created")
                    invited_user_id = str(inserted["id"])
                else:
                    invited_user_id = str(existing["id"])
                cursor.execute(
                    "DELETE FROM user_invitations WHERE user_id = %s", (invited_user_id,)
                )
                cursor.execute(
                    """
                    INSERT INTO user_invitations (token_hash, user_id, expires_at)
                    VALUES (%s, %s, %s)
                    """,
                    (token_hash, invited_user_id, expires_at),
                )
                cursor.execute(
                    """
                    SELECT id::text, email, role, is_active, true AS invitation_pending,
                           created_at, updated_at
                    FROM users WHERE id = %s
                    """,
                    (invited_user_id,),
                )
                row = cursor.fetchone()
        if row is None:
            raise RuntimeError("invited user was not found")
        return _user_summary_from_row(row)

    def accept_user_invitation(self, token_hash: str, password_hash: str, *, now: datetime) -> bool:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT user_id FROM user_invitations
                    WHERE token_hash = %s AND accepted_at IS NULL AND expires_at > %s
                    FOR UPDATE
                    """,
                    (token_hash, now),
                )
                invitation = cursor.fetchone()
                if invitation is None:
                    return False
                cursor.execute(
                    """
                    UPDATE users SET password_hash = %s, is_active = true, updated_at = now()
                    WHERE id = %s AND password_hash IS NULL
                    """,
                    (password_hash, invitation["user_id"]),
                )
                if cursor.rowcount != 1:
                    return False
                cursor.execute(
                    "UPDATE user_invitations SET accepted_at = %s WHERE token_hash = %s",
                    (now, token_hash),
                )
        return True

    def create_session(
        self, token_hash: str, user_id: str, *, expires_at: datetime
    ) -> AuthenticatedUser:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id::text, email, role, is_active, created_at, updated_at
                    FROM users WHERE id = %s AND is_active = true
                    FOR SHARE
                    """,
                    (user_id,),
                )
                user_row = cursor.fetchone()
                if user_row is None:
                    raise RuntimeError("session user is unavailable")
                cursor.execute("DELETE FROM sessions WHERE expires_at <= now()")
                cursor.execute(
                    """
                    INSERT INTO sessions (token_hash, user_id, expires_at)
                    VALUES (%s, %s, %s)
                    RETURNING expires_at
                    """,
                    (token_hash, user_id, expires_at),
                )
                session_row = cursor.fetchone()
        if session_row is None:
            raise RuntimeError("session user is unavailable")
        return _authenticated_user_from_rows(user_row, session_row["expires_at"])

    def get_authenticated_user(self, token_hash: str, *, now: datetime) -> AuthenticatedUser | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT users.id::text, users.email, users.role, users.is_active,
                           users.created_at, users.updated_at, sessions.expires_at
                    FROM sessions
                    JOIN users ON users.id = sessions.user_id
                    WHERE sessions.token_hash = %s
                      AND sessions.expires_at > %s
                      AND users.is_active = true
                    """,
                    (token_hash, now),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        return _authenticated_user_from_rows(row, row["expires_at"])

    def delete_session(self, token_hash: str) -> None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))

    def user_can_access_project(self, user_id: str, project_id: str) -> bool:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM project_members
                        WHERE user_id = %s AND project_id = %s
                    ) AS allowed
                    """,
                    (user_id, project_id),
                )
                row = cursor.fetchone()
        return bool(row and row["allowed"] is True)

    def list_project_member_ids(self, project_id: str) -> list[str] | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
                if cursor.fetchone() is None:
                    return None
                cursor.execute(
                    """
                    SELECT user_id::text AS user_id FROM project_members
                    WHERE project_id = %s ORDER BY user_id
                    """,
                    (project_id,),
                )
                rows = cursor.fetchall()
        return [str(row["user_id"]) for row in rows]

    def replace_project_members(self, project_id: str, user_ids: Sequence[str]) -> bool:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM projects WHERE id = %s FOR UPDATE", (project_id,))
                if cursor.fetchone() is None:
                    return False
                self._replace_project_members_with_cursor(cursor, project_id, user_ids)
        return True

    @staticmethod
    def _replace_project_members_with_cursor(
        cursor: Any, project_id: str, user_ids: Sequence[str]
    ) -> None:
        unique_user_ids = sorted(set(user_ids))
        cursor.execute(
            "SELECT user_id::text AS user_id FROM project_members WHERE project_id = %s",
            (project_id,),
        )
        existing_user_ids = {str(row["user_id"]) for row in cursor.fetchall()}
        if unique_user_ids:
            cursor.execute(
                """
                SELECT id::text AS id, is_active FROM users
                WHERE id = ANY(%s::uuid[]) AND role = 'USER'
                """,
                (unique_user_ids,),
            )
            users = {str(row["id"]): bool(row["is_active"]) for row in cursor.fetchall()}
            if len(users) != len(unique_user_ids) or any(
                not users[user_id] and user_id not in existing_user_ids
                for user_id in unique_user_ids
            ):
                raise InvalidProjectMembersError("invalid project members")
        cursor.execute("DELETE FROM project_members WHERE project_id = %s", (project_id,))
        if unique_user_ids:
            cursor.executemany(
                "INSERT INTO project_members (project_id, user_id) VALUES (%s, %s)",
                [(project_id, user_id) for user_id in unique_user_ids],
            )

    def create_project(self, project: ProjectCreate) -> Project:
        self.ensure_schema()
        project_id = str(uuid4())
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO projects (id, name, description, assigned_to_viewer)
                    VALUES (%s, %s, %s, %s)
                    RETURNING *, NULL::jsonb AS latest_scan
                    """,
                    (
                        project_id,
                        project.name.strip(),
                        project.description.strip(),
                        project.assigned_to_viewer,
                    ),
                )
                row = cursor.fetchone()
                if row is not None:
                    self._replace_project_members_with_cursor(
                        cursor, project_id, project.member_user_ids
                    )
        if row is None:
            raise RuntimeError("project insert returned no row")
        return _project_from_row(row)

    def list_projects(
        self,
        *,
        query: str | None,
        language: str | None,
        limit: int,
        offset: int,
        member_user_id: str | None = None,
    ) -> ProjectList:
        self.ensure_schema()
        normalized_query = (query or "").strip()
        normalized_language = (language or "").strip()
        filters = (
            normalized_query,
            normalized_query,
            normalized_language,
            normalized_language,
            member_user_id,
            member_user_id,
        )
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT count(*) AS total
                    FROM projects AS project
                    LEFT JOIN LATERAL (
                        SELECT scan.detected_languages FROM scan_runs AS scan
                        WHERE scan.project_id = project.id
                        ORDER BY scan.created_at DESC, scan.id DESC LIMIT 1
                    ) AS latest_scan ON TRUE
                    WHERE (%s = '' OR position(
                        lower(%s::text)
                        in lower(concat_ws(' ', project.name, project.description))
                    ) > 0)
                      AND (%s = '' OR latest_scan.detected_languages ? %s::text)
                      AND (%s::uuid IS NULL OR EXISTS (
                          SELECT 1 FROM project_members AS member
                          WHERE member.project_id = project.id AND member.user_id = %s::uuid
                      ))
                    """,
                    filters,
                )
                total_row = cursor.fetchone()
                cursor.execute(
                    """
                    SELECT project.*, row_to_json(latest_scan) AS latest_scan
                    FROM projects AS project
                    LEFT JOIN LATERAL (
                        SELECT
                            scan.id, scan.project_id, scan.archive_name, scan.status,
                            scan.phase, scan.progress_percent, scan.completed_units,
                            scan.total_units, scan.message, scan.detected_languages,
                            scan.language_file_counts, scan.archive_file_count,
                            scan.analysis_file_count, scan.engine_name, scan.engine_version,
                            scan.rulepack_name, scan.rulepack_version, scan.ruleset_digest,
                            scan.registered_rule_count, scan.supported_rule_count,
                            scan.error_code, scan.created_at, scan.updated_at
                        FROM scan_runs AS scan
                        WHERE scan.project_id = project.id
                        ORDER BY scan.created_at DESC, scan.id DESC LIMIT 1
                    ) AS latest_scan ON TRUE
                    WHERE (%s = '' OR position(
                        lower(%s::text)
                        in lower(concat_ws(' ', project.name, project.description))
                    ) > 0)
                      AND (%s = '' OR latest_scan.detected_languages ? %s::text)
                      AND (%s::uuid IS NULL OR EXISTS (
                          SELECT 1 FROM project_members AS member
                          WHERE member.project_id = project.id AND member.user_id = %s::uuid
                      ))
                    ORDER BY project.updated_at DESC, project.id
                    LIMIT %s OFFSET %s
                    """,
                    (*filters, limit, offset),
                )
                rows = cursor.fetchall()
        return ProjectList(
            items=[_project_from_row(row) for row in rows],
            total=int(total_row["total"] if total_row else 0),
            limit=limit,
            offset=offset,
        )

    def get_project(self, project_id: str) -> Project | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT project.*, row_to_json(latest_scan) AS latest_scan
                    FROM projects AS project
                    LEFT JOIN LATERAL (
                        SELECT
                            scan.id, scan.project_id, scan.archive_name, scan.status,
                            scan.phase, scan.progress_percent, scan.completed_units,
                            scan.total_units, scan.message, scan.detected_languages,
                            scan.language_file_counts, scan.archive_file_count,
                            scan.analysis_file_count, scan.engine_name, scan.engine_version,
                            scan.rulepack_name, scan.rulepack_version, scan.ruleset_digest,
                            scan.registered_rule_count, scan.supported_rule_count,
                            scan.error_code, scan.created_at, scan.updated_at
                        FROM scan_runs AS scan
                        WHERE scan.project_id = project.id
                        ORDER BY scan.created_at DESC, scan.id DESC LIMIT 1
                    ) AS latest_scan ON TRUE
                    WHERE project.id = %s
                    """,
                    (project_id,),
                )
                row = cursor.fetchone()
        return _project_from_row(row) if row else None

    def update_project(self, project_id: str, project: ProjectUpdate) -> Project | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE projects SET name = %s, description = %s, assigned_to_viewer = %s,
                        updated_at = now()
                    WHERE id = %s RETURNING *
                    """,
                    (
                        project.name.strip(),
                        project.description.strip(),
                        project.assigned_to_viewer,
                        project_id,
                    ),
                )
                row = cursor.fetchone()
                if row is not None:
                    self._replace_project_members_with_cursor(
                        cursor, project_id, project.member_user_ids
                    )
        if row is None:
            return None
        row["latest_scan"] = None
        current = self.get_project(project_id)
        return current or _project_from_row(row)

    def delete_project(self, project_id: str) -> bool:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM projects WHERE id = %s FOR UPDATE",
                    (project_id,),
                )
                if cursor.fetchone() is None:
                    return False
                cursor.execute(
                    """
                    SELECT id FROM scan_runs
                    WHERE project_id = %s AND status IN ('PENDING', 'RUNNING')
                    LIMIT 1 FOR UPDATE
                    """,
                    (project_id,),
                )
                if cursor.fetchone() is not None:
                    raise ProjectHasActiveScansError(project_id)
                cursor.execute(
                    """
                    INSERT INTO deleted_scan_workspaces (scan_id)
                    SELECT id FROM scan_runs WHERE project_id = %s
                    ON CONFLICT (scan_id) DO NOTHING
                    """,
                    (project_id,),
                )
                cursor.execute(
                    "SELECT set_config('toy_sast.project_cascade_delete', %s, true)",
                    (project_id,),
                )
                cursor.execute("DELETE FROM projects WHERE id = %s", (project_id,))
                return cursor.rowcount == 1

    def list_project_scans(self, project_id: str, *, limit: int, offset: int) -> ScanList:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM projects WHERE id = %s", (project_id,))
                if cursor.fetchone() is None:
                    raise ProjectNotFoundError(project_id)
                cursor.execute(
                    "SELECT count(*) AS total FROM scan_runs WHERE project_id = %s",
                    (project_id,),
                )
                total_row = cursor.fetchone()
                cursor.execute(
                    """
                    SELECT
                        id, project_id, archive_name, status, phase, progress_percent,
                        completed_units, total_units, message, detected_languages,
                        language_file_counts, archive_file_count, analysis_file_count,
                        engine_name, engine_version, rulepack_name, rulepack_version,
                        ruleset_digest, registered_rule_count, supported_rule_count,
                        error_code, created_at, updated_at
                    FROM scan_runs WHERE project_id = %s
                    ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s
                    """,
                    (project_id, limit, offset),
                )
                rows = cursor.fetchall()
        return ScanList(
            items=[_progress_from_row(row) for row in rows],
            total=int(total_row["total"] if total_row else 0),
            limit=limit,
            offset=offset,
        )

    def create_scan(
        self, scan_id: str, project_id: str, archive_name: str, archive_data: bytes
    ) -> ScanProgress:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM projects WHERE id = %s FOR SHARE", (project_id,))
                if cursor.fetchone() is None:
                    raise ProjectNotFoundError(project_id)
                cursor.execute(
                    """
                    INSERT INTO scan_runs (
                        id, project_id, archive_name, archive_data, status, phase, message
                    ) VALUES (%s, %s, %s, %s, 'PENDING', 'PENDING', %s)
                    RETURNING
                        id, project_id, archive_name, status, phase, progress_percent,
                        completed_units, total_units, message, detected_languages,
                        language_file_counts, archive_file_count, analysis_file_count,
                        engine_name, engine_version, rulepack_name, rulepack_version,
                        ruleset_digest, registered_rule_count, supported_rule_count,
                        error_code, created_at, updated_at
                    """,
                    (scan_id, project_id, archive_name, archive_data, "분석 작업이 대기 중입니다."),
                )
                row = cursor.fetchone()
                cursor.execute(
                    "INSERT INTO scan_jobs (scan_id, status) VALUES (%s, 'PENDING')",
                    (scan_id,),
                )
        if row is None:
            raise RuntimeError("scan insert returned no row")
        return _progress_from_row(row)

    def get_scan(self, scan_id: str) -> ScanProgress | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id, project_id, archive_name, status, phase, progress_percent,
                        completed_units, total_units, message, detected_languages,
                        language_file_counts, archive_file_count, analysis_file_count,
                        engine_name, engine_version, rulepack_name, rulepack_version,
                        ruleset_digest, registered_rule_count, supported_rule_count,
                        error_code, created_at, updated_at
                    FROM scan_runs WHERE id = %s
                    """,
                    (scan_id,),
                )
                row = cursor.fetchone()
        return _progress_from_row(row) if row else None

    def get_results(self, scan_id: str) -> ScanResults | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT status, detected_languages, supported_rule_count, rulepack_version,
                           issue_model_version
                    FROM scan_runs WHERE id = %s
                    """,
                    (scan_id,),
                )
                scan = cursor.fetchone()
                if not scan or scan["status"] != "COMPLETED":
                    return None
                reader = (
                    _issue_snapshot_reader(scan.get("issue_model_version"))
                    if scan.get("issue_model_version") is not None
                    else None
                )
                cursor.execute(
                    """
                    SELECT result FROM scan_weakness_results
                    WHERE scan_id = %s ORDER BY (result->>'number')::integer
                    """,
                    (scan_id,),
                )
                rows = cursor.fetchall()
                issue_rows: list[dict[str, Any]] = []
                language_rows: list[dict[str, Any]] = []
                if reader is not None:
                    cursor.execute(
                        """
                        SELECT * FROM scan_issues WHERE scan_id = %s
                        ORDER BY weakness_number, path COLLATE "C", start_line,
                                 start_column, issue_id
                        """,
                        (scan_id,),
                    )
                    issue_rows = cursor.fetchall()
                    if reader.model_version == 2:
                        cursor.execute(
                            """
                            SELECT weakness_id, weakness_number, language,
                                   support_status, result_status, executed_rule_count,
                                   finding_count, reason
                            FROM scan_language_results WHERE scan_id = %s
                            """,
                            (scan_id,),
                        )
                        language_rows = cursor.fetchall()
        stored_items = [cast(JsonObject, row["result"]) for row in rows]
        if reader is not None:
            if reader.model_version == 2:
                try:
                    criteria = _validate_stored_criterion_snapshots(stored_items)
                    language_results = _validate_stored_language_results(
                        language_rows, scan["detected_languages"]
                    )
                    issues = reader.validate_issues(issue_rows)
                    coverage_items = _coverage_items_v2(
                        criteria, language_results, scan["detected_languages"]
                    )
                    v2_findings_by_weakness: dict[str, list[dict[str, Any]]] = {
                        item.weakness_id: [] for item in coverage_items
                    }
                    for issue in issues:
                        v2_findings_by_weakness[issue.weakness_id].append(
                            {
                                "rule_id": issue.rule_id,
                                "kind": issue.finding_kind,
                                "language": issue.language,
                                "path": issue.path,
                                "start_line": issue.start_line,
                                "message": issue.message,
                                "severity": issue.severity,
                            }
                        )
                    validated_results = []
                    for item in coverage_items:
                        findings = v2_findings_by_weakness[item.weakness_id]
                        supported = any(
                            row.support_status.value == "SUPPORTED" for row in item.languages
                        )
                        check_failed = any(
                            row.result_status.value == "CHECK_FAILED" for row in item.languages
                        )
                        validated_results.append(
                            WeaknessResult(
                                weakness_id=item.weakness_id,
                                number=item.number,
                                category=item.category,
                                category_number=item.category_number,
                                name=item.name,
                                description=item.description,
                                sast_classification=item.sast_classification,
                                implementation_status=None,
                                support_status="SUPPORTED" if supported else "NOT_SUPPORTED",
                                result_status=(
                                    "DETECTED"
                                    if findings
                                    else "CHECK_FAILED"
                                    if check_failed
                                    else "NOT_DETECTED"
                                    if supported
                                    else "NOT_SUPPORTED"
                                ),
                                reason="언어별 v2 결과의 호환 요약입니다.",
                                finding_count=len(findings),
                                findings=findings,
                            )
                        )
                except (KeyError, TypeError, ValueError) as exc:
                    raise CorruptScanIssueModelError(
                        "stored v2 result snapshot is inconsistent"
                    ) from exc
                return ScanResults.model_validate(
                    {
                        "scan_id": scan_id,
                        "status": scan["status"],
                        "detected_languages": scan["detected_languages"],
                        "supported_rule_count": scan["supported_rule_count"],
                        "rulepack_version": scan["rulepack_version"],
                        "total_weakness_count": len(validated_results),
                        "results": validated_results,
                    }
                )
            try:
                coverage = reader.validate_coverage(stored_items)
                issues = reader.validate_issues(issue_rows)
                _validate_issue_coverage_relationship(coverage, issues)
            except (KeyError, TypeError, ValueError) as exc:
                raise CorruptScanIssueModelError("stored result snapshot is inconsistent") from exc
            findings_by_weakness: dict[str, list[dict[str, Any]]] = {
                item.weakness_id: [] for item in coverage
            }
            for issue in issues:
                findings_by_weakness[issue.weakness_id].append(
                    {
                        "rule_id": issue.rule_id,
                        "kind": issue.finding_kind,
                        "language": issue.language,
                        "path": issue.path,
                        "start_line": issue.start_line,
                        "message": issue.message,
                        "severity": issue.severity,
                    }
                )
            try:
                validated_results = [
                    WeaknessResult.model_validate(
                        {
                            **item.model_dump(mode="json"),
                            "finding_count": len(findings_by_weakness[item.weakness_id]),
                            "findings": findings_by_weakness[item.weakness_id],
                        }
                    )
                    for item in coverage
                ]
                validated_results = _validate_stored_results(
                    [item.model_dump(mode="json") for item in validated_results]
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise CorruptScanIssueModelError("stored result snapshot is inconsistent") from exc
        else:
            validated_results = _validate_stored_results(stored_items)
        return ScanResults.model_validate(
            {
                "scan_id": scan_id,
                "status": scan["status"],
                "detected_languages": scan["detected_languages"],
                "supported_rule_count": scan["supported_rule_count"],
                "rulepack_version": scan["rulepack_version"],
                "total_weakness_count": len(validated_results),
                "results": validated_results,
            }
        )

    def get_scan_files(
        self,
        scan_id: str,
        *,
        parent_path: str | None,
        limit: int,
        cursor: str | None,
    ) -> ScanFileList | None:
        self.ensure_schema()
        normalized_parent = _normalize_manifest_query_path(parent_path)
        cursor_position = (
            self._decode_scan_files_cursor(cursor, scan_id, normalized_parent)
            if cursor is not None
            else None
        )
        with self._connect() as connection:
            with connection.cursor() as database_cursor:
                database_cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                database_cursor.execute(
                    """
                    SELECT
                        status, manifest_version, manifest_node_count,
                        manifest_summary_version, manifest_root_count,
                        manifest_directory_count, manifest_file_count,
                        manifest_finding_count, archive_file_count, analysis_file_count,
                        issue_model_version, issue_summary_version,
                        detected_languages, coverage_result_count,
                        language_coverage_result_count, issue_count, detected_issue_count,
                        review_signal_count, issue_error_count, issue_warning_count,
                        issue_info_count, issue_counts_by_weakness
                    FROM scan_runs WHERE id = %s
                    """,
                    (scan_id,),
                )
                scan = database_cursor.fetchone()
                if scan is None:
                    return None
                if scan["status"] != "COMPLETED":
                    raise ScanFilesNotReadyError(scan_id)
                manifest_version = scan["manifest_version"]
                manifest_node_count = scan["manifest_node_count"]
                if manifest_version is None and manifest_node_count is None:
                    database_cursor.execute(
                        "SELECT count(*) AS node_count FROM scan_files WHERE scan_id = %s",
                        (scan_id,),
                    )
                    count_row = database_cursor.fetchone()
                    actual_node_count = int(count_row["node_count"] if count_row else -1)
                    if actual_node_count != 0:
                        raise CorruptScanManifestError(
                            "legacy scan unexpectedly contains manifest nodes"
                        )
                    return ScanFileList(
                        scan_id=scan_id,
                        manifest_available=False,
                        manifest_version=None,
                        unavailable_reason=ManifestUnavailableReason.LEGACY_SCAN,
                        parent_path=normalized_parent,
                    )
                try:
                    manifest_summary = _manifest_snapshot_summary_from_scan(scan)
                    if (
                        scan.get("issue_model_version") is not None
                        and manifest_summary.finding_count
                        != _issue_snapshot_reader(scan.get("issue_model_version"))
                        .validate_summary(scan)
                        .stats.total_issue_count
                    ):
                        raise ValueError(
                            "manifest findings do not match the normalized issue snapshot"
                        )
                except (KeyError, TypeError, ValueError) as exc:
                    raise CorruptScanManifestError(
                        "manifest snapshot summary is inconsistent"
                    ) from exc
                if normalized_parent is not None:
                    database_cursor.execute(
                        """
                        SELECT node.path, node.parent_path, node.depth, node.node_type,
                               node.size, node.language, node.state, node.finding_count,
                               EXISTS (
                                   SELECT 1 FROM scan_files AS child
                                   WHERE child.scan_id = node.scan_id
                                     AND child.parent_path = node.path
                               ) AS has_children
                        FROM scan_files AS node
                        WHERE node.scan_id = %s AND node.path = %s
                        """,
                        (scan_id, normalized_parent),
                    )
                    parent_row = database_cursor.fetchone()
                    if parent_row is None:
                        raise ScanFileParentNotFoundError(normalized_parent)
                    try:
                        parent = _scan_file_node_from_row(parent_row)
                    except ValueError as exc:
                        raise CorruptScanManifestError(
                            "manifest parent payload is invalid"
                        ) from exc
                    if parent.entry_type is not ScanFileType.DIRECTORY:
                        raise ScanFileParentNotFoundError(normalized_parent)

                page_where = "node.scan_id = %s AND node.parent_path IS NOT DISTINCT FROM %s"
                page_parameters: list[object] = [scan_id, normalized_parent]
                if cursor_position is not None:
                    page_where += """
                        AND (
                            CASE WHEN node.node_type = 'DIRECTORY' THEN 0 ELSE 1 END,
                            node.path COLLATE "C"
                        ) > (%s, %s::text COLLATE "C")
                    """
                    page_parameters.extend(cursor_position)
                database_cursor.execute(
                    f"""
                    SELECT node.path, node.parent_path, node.depth, node.node_type,
                           node.size, node.language, node.state, node.finding_count,
                           EXISTS (
                               SELECT 1 FROM scan_files AS child
                               WHERE child.scan_id = node.scan_id
                                 AND child.parent_path = node.path
                           ) AS has_children
                    FROM scan_files AS node
                    WHERE {page_where}
                    ORDER BY CASE WHEN node.node_type = 'DIRECTORY' THEN 0 ELSE 1 END,
                             node.path COLLATE "C"
                    LIMIT %s
                    """,  # noqa: S608 -- clauses are fixed literals
                    (*page_parameters, limit + 1),
                )
                manifest_rows = database_cursor.fetchall()

        try:
            page_candidates = [_scan_file_node_from_row(row) for row in manifest_rows]
        except ValueError as exc:
            raise CorruptScanManifestError("manifest node payload is invalid") from exc
        page = page_candidates[:limit]
        next_cursor = None
        if len(page_candidates) > limit and page:
            last = page[-1]
            rank = 0 if last.entry_type is ScanFileType.DIRECTORY else 1
            next_cursor = self._encode_scan_files_cursor(
                scan_id, normalized_parent, rank, last.path
            )
        return ScanFileList(
            scan_id=scan_id,
            manifest_available=True,
            manifest_version=MANIFEST_VERSION,
            parent_path=normalized_parent,
            items=page,
            next_cursor=next_cursor,
        )

    def _encode_scan_files_cursor(
        self, scan_id: str, parent_path: str | None, rank: int, path: str
    ) -> str:
        payload = json.dumps(
            {"v": 1, "s": scan_id, "p": parent_path, "r": rank, "k": path},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(self._cursor_secret, payload, hashlib.sha256).digest()
        return f"{_base64url_encode(payload)}.{_base64url_encode(signature)}"

    def _decode_scan_files_cursor(
        self, cursor: str, scan_id: str, parent_path: str | None
    ) -> tuple[int, str]:
        if not cursor or len(cursor) > 8192 or cursor.count(".") != 1:
            raise InvalidScanFilesCursorError("cursor format is invalid")
        encoded_payload, encoded_signature = cursor.split(".")
        try:
            payload = _base64url_decode(encoded_payload)
            signature = _base64url_decode(encoded_signature)
            decoded = json.loads(payload)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidScanFilesCursorError("cursor format is invalid") from exc
        expected_signature = hmac.new(self._cursor_secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise InvalidScanFilesCursorError("cursor signature is invalid")
        if not isinstance(decoded, dict) or set(decoded) != {"v", "s", "p", "r", "k"}:
            raise InvalidScanFilesCursorError("cursor payload is invalid")
        rank = decoded["r"]
        path = decoded["k"]
        if (
            decoded["v"] != 1
            or decoded["s"] != scan_id
            or decoded["p"] != parent_path
            or type(rank) is not int
            or rank not in {0, 1}
            or not isinstance(path, str)
        ):
            raise InvalidScanFilesCursorError("cursor context is invalid")
        try:
            if normalize_archive_path(path) != path:
                raise InvalidScanFilesCursorError("cursor path is invalid")
        except UnsafeArchiveError as exc:
            raise InvalidScanFilesCursorError("cursor path is invalid") from exc
        return rank, path

    def get_scan_issues(
        self,
        scan_id: str,
        *,
        filters: IssueFilters,
        limit: int,
        cursor: str | None,
    ) -> IssueList | None:
        self.ensure_schema()
        normalized_filters = _validate_issue_filters(filters)
        cursor_position = (
            self._decode_issues_cursor(cursor, scan_id, normalized_filters)
            if cursor is not None
            else None
        )
        with self._connect() as connection:
            with connection.cursor() as database_cursor:
                database_cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                database_cursor.execute(
                    """
                    SELECT status, issue_model_version,
                           engine_name, engine_version, rulepack_name, rulepack_version,
                           ruleset_digest, registered_rule_count, supported_rule_count,
                           detected_languages, issue_summary_version,
                           coverage_result_count, language_coverage_result_count, issue_count,
                           detected_issue_count, review_signal_count,
                           issue_error_count, issue_warning_count, issue_info_count,
                           issue_counts_by_weakness
                    FROM scan_runs WHERE id = %s
                    """,
                    (scan_id,),
                )
                scan = database_cursor.fetchone()
                if scan is None:
                    return None
                if scan["status"] != "COMPLETED":
                    raise ScanIssuesNotReadyError(scan_id)
                if scan["issue_model_version"] is None:
                    database_cursor.execute(
                        """
                        SELECT
                            (SELECT count(*) FROM scan_weakness_results WHERE scan_id = %s)
                                AS coverage_count,
                            (SELECT count(*) FROM scan_issues WHERE scan_id = %s)
                                AS issue_count
                        """,
                        (scan_id, scan_id),
                    )
                    counts = database_cursor.fetchone()
                    coverage_count = int(counts["coverage_count"] if counts else -1)
                    issue_count = int(counts["issue_count"] if counts else -1)
                    if issue_count != 0 or coverage_count != 49:
                        raise CorruptScanIssueModelError(
                            "legacy result storage is incomplete or contains normalized issues"
                        )
                    return IssueList(
                        scan_id=scan_id,
                        issue_model_available=False,
                        unavailable_reason=IssueUnavailableReason.LEGACY_SCAN,
                        total=0,
                        limit=limit,
                    )
                reader = _issue_snapshot_reader(scan["issue_model_version"])
                try:
                    snapshot = reader.validate_summary(scan)
                except (KeyError, TypeError, ValueError) as exc:
                    raise CorruptScanIssueModelError(
                        "issue snapshot summary is inconsistent"
                    ) from exc

                self._validate_issue_path_filter(database_cursor, scan_id, normalized_filters)
                where_sql, parameters = _issue_filter_sql(scan_id, normalized_filters)
                database_cursor.execute(
                    f"SELECT count(*) AS total FROM scan_issues AS issue WHERE {where_sql}",  # noqa: S608 -- clauses are fixed literals
                    parameters,
                )
                total_row = database_cursor.fetchone()
                total = int(total_row["total"] if total_row else 0)
                page_where = where_sql
                page_parameters = list(parameters)
                if cursor_position is not None:
                    page_where += """
                        AND (
                            issue.weakness_number,
                            issue.path COLLATE "C",
                            issue.start_line,
                            issue.start_column,
                            issue.issue_id
                        ) > (%s, %s::text COLLATE "C", %s, %s, %s::uuid)
                    """
                    page_parameters.extend(cursor_position)
                database_cursor.execute(
                    f"""
                    SELECT issue.* FROM scan_issues AS issue
                    WHERE {page_where}
                    ORDER BY issue.weakness_number, issue.path COLLATE "C",
                             issue.start_line, issue.start_column, issue.issue_id
                    LIMIT %s
                    """,  # noqa: S608 -- clauses are fixed literals
                    (*page_parameters, limit + 1),
                )
                rows = database_cursor.fetchall()

        try:
            candidates = [reader.list_item(row) for row in rows]
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptScanIssueModelError("issue page payload is invalid") from exc
        page = candidates[:limit]
        next_cursor = None
        if len(candidates) > limit and page:
            last = page[-1]
            next_cursor = self._encode_issues_cursor(
                scan_id,
                normalized_filters,
                (
                    last.weakness_number,
                    last.path,
                    last.start_line,
                    last.start_column,
                    last.issue_id,
                ),
            )
        return IssueList(
            scan_id=scan_id,
            issue_model_available=True,
            items=page,
            total=total,
            limit=limit,
            next_cursor=next_cursor,
            stats=(
                _v2_issue_stats(snapshot.stats) if reader.model_version == 2 else snapshot.stats
            ),
        )

    def get_scan_issue(self, scan_id: str, issue_id: str) -> IssueDetail | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                cursor.execute(
                    """
                    SELECT status, issue_model_version,
                           engine_name, engine_version, rulepack_name, rulepack_version,
                           ruleset_digest, registered_rule_count, supported_rule_count,
                           detected_languages, issue_summary_version,
                           coverage_result_count, language_coverage_result_count, issue_count,
                           detected_issue_count, review_signal_count,
                           issue_error_count, issue_warning_count, issue_info_count,
                           issue_counts_by_weakness
                    FROM scan_runs WHERE id = %s
                    """,
                    (scan_id,),
                )
                scan = cursor.fetchone()
                if scan is None:
                    return None
                if scan["status"] != "COMPLETED":
                    raise ScanIssuesNotReadyError(scan_id)
                if scan["issue_model_version"] is None:
                    cursor.execute(
                        "SELECT count(*) AS count FROM scan_issues WHERE scan_id = %s",
                        (scan_id,),
                    )
                    count_row = cursor.fetchone()
                    if count_row is None or int(count_row["count"]) != 0:
                        raise CorruptScanIssueModelError(
                            "legacy scan unexpectedly contains normalized issues"
                        )
                    raise LegacyIssueModelUnavailableError(scan_id)
                reader = _issue_snapshot_reader(scan["issue_model_version"])
                try:
                    reader.validate_summary(scan)
                    engine_snapshot = _engine_snapshot_from_row(scan)
                except (KeyError, TypeError, ValueError) as exc:
                    raise CorruptScanIssueModelError(
                        "issue snapshot summary is inconsistent"
                    ) from exc
                cursor.execute(
                    """
                    SELECT * FROM scan_issues
                    WHERE scan_id = %s AND issue_id = %s
                    """,
                    (scan_id, issue_id),
                )
                row = cursor.fetchone()
        if row is None:
            return None
        try:
            return reader.detail(row, engine_snapshot=engine_snapshot)
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptScanIssueModelError("issue detail payload is invalid") from exc

    def get_scan_coverage(self, scan_id: str) -> ScanCoverage | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                cursor.execute(
                    """
                    SELECT status, issue_model_version,
                           engine_name, engine_version, rulepack_name, rulepack_version,
                           ruleset_digest, registered_rule_count, supported_rule_count,
                           detected_languages, issue_summary_version,
                           coverage_result_count, language_coverage_result_count, issue_count,
                           detected_issue_count, review_signal_count,
                           issue_error_count, issue_warning_count, issue_info_count,
                           issue_counts_by_weakness
                    FROM scan_runs WHERE id = %s
                    """,
                    (scan_id,),
                )
                scan = cursor.fetchone()
                if scan is None:
                    return None
                if scan["status"] != "COMPLETED":
                    raise ScanIssuesNotReadyError(scan_id)
                if scan["issue_model_version"] is not None:
                    reader = _issue_snapshot_reader(scan["issue_model_version"])
                    try:
                        snapshot = reader.validate_summary(scan)
                        _engine_snapshot_from_row(scan)
                    except (KeyError, TypeError, ValueError) as exc:
                        raise CorruptScanIssueModelError(
                            "issue snapshot summary is inconsistent"
                        ) from exc
                    cursor.execute(
                        """
                        SELECT result FROM scan_weakness_results
                        WHERE scan_id = %s ORDER BY (result->>'number')::integer
                        """,
                        (scan_id,),
                    )
                    coverage_rows = cursor.fetchall()
                    if reader.model_version == 2:
                        cursor.execute(
                            """
                            SELECT weakness_id, weakness_number, language,
                                   support_status, result_status, executed_rule_count,
                                   finding_count, reason
                            FROM scan_language_results
                            WHERE scan_id = %s
                            ORDER BY weakness_number,
                              CASE language
                                WHEN 'Java' THEN 1
                                WHEN 'JavaScript' THEN 2
                                WHEN 'Python' THEN 3
                              END
                            """,
                            (scan_id,),
                        )
                        language_rows = cursor.fetchall()
                        try:
                            criteria = _validate_stored_criterion_snapshots(
                                [cast(JsonObject, row["result"]) for row in coverage_rows]
                            )
                            language_results = _validate_stored_language_results(
                                language_rows, scan["detected_languages"]
                            )
                            v2_items = _coverage_items_v2(
                                criteria, language_results, scan["detected_languages"]
                            )
                            _validate_v2_coverage_issue_relationship(
                                v2_items, snapshot.counts_by_weakness
                            )
                        except (KeyError, TypeError, ValueError) as exc:
                            raise CorruptScanIssueModelError(
                                "coverage model v2 snapshot is inconsistent"
                            ) from exc
                        return ScanCoverage(
                            scan_id=scan_id,
                            coverage_model_version=2,
                            summary=_coverage_summary_v2(v2_items, issue_stats=snapshot.stats),
                            items=v2_items,
                        )
                    try:
                        coverage = reader.validate_coverage(
                            [cast(JsonObject, row["result"]) for row in coverage_rows]
                        )
                        _validate_coverage_count_relationship(coverage, snapshot.counts_by_weakness)
                    except (KeyError, TypeError, ValueError) as exc:
                        raise CorruptScanIssueModelError(
                            "coverage snapshot is inconsistent"
                        ) from exc
                    legacy_items = [
                        CoverageItem(
                            **item.model_dump(mode="json"),
                            finding_count=snapshot.counts_by_weakness.get(item.weakness_id, 0),
                        )
                        for item in coverage
                    ]
                    return ScanCoverage(
                        scan_id=scan_id,
                        coverage_model_version=reader.model_version,
                        summary=_coverage_summary(legacy_items, issue_stats=snapshot.stats),
                        items=legacy_items,
                        legacy_notice=("이전 결과 모델로 생성됨 · 현재 기준으로 다시 분석 필요"),
                    )
                cursor.execute(
                    """
                    SELECT result FROM scan_weakness_results
                    WHERE scan_id = %s ORDER BY (result->>'number')::integer
                    """,
                    (scan_id,),
                )
                coverage_rows = cursor.fetchall()
                cursor.execute(
                    "SELECT count(*) AS issue_count FROM scan_issues WHERE scan_id = %s",
                    (scan_id,),
                )
                issue_count_row = cursor.fetchone()
        stored_payloads = [cast(JsonObject, row["result"]) for row in coverage_rows]
        stored_issue_count = int(
            issue_count_row["issue_count"] if issue_count_row is not None else -1
        )
        if scan["issue_model_version"] is not None or stored_issue_count != 0:
            raise CorruptScanIssueModelError("legacy issue model snapshot is inconsistent")
        legacy = _validate_stored_results(stored_payloads)
        legacy_items = [
            CoverageItem(
                **{
                    key: value
                    for key, value in item.model_dump(mode="json").items()
                    if key not in {"findings", "finding_count"}
                },
                finding_count=item.finding_count,
            )
            for item in legacy
        ]
        return ScanCoverage(
            scan_id=scan_id,
            coverage_model_version=None,
            summary=_coverage_summary(legacy_items, issue_stats=None),
            items=legacy_items,
            legacy_notice="이전 결과 모델로 생성됨 · 현재 기준으로 다시 분석 필요",
        )

    def _validate_issue_path_filter(
        self,
        cursor: Any,
        scan_id: str,
        filters: IssueFilters,
    ) -> None:
        if filters.path is None:
            return
        cursor.execute(
            """
            SELECT node_type FROM scan_files WHERE scan_id = %s AND path = %s
            """,
            (scan_id, filters.path),
        )
        row = cursor.fetchone()
        expected_type = filters.path_scope.value if filters.path_scope else None
        if row is None or row["node_type"] != expected_type:
            raise InvalidIssueFilterError("path and pathScope do not identify that manifest node")

    def _encode_issues_cursor(
        self,
        scan_id: str,
        filters: IssueFilters,
        position: tuple[int, str, int, int, str],
    ) -> str:
        payload = json.dumps(
            {
                "v": 1,
                "s": scan_id,
                "f": filters.cursor_payload(),
                "k": list(position),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(self._cursor_secret, payload, hashlib.sha256).digest()
        return f"{_base64url_encode(payload)}.{_base64url_encode(signature)}"

    def _decode_issues_cursor(
        self, cursor: str, scan_id: str, filters: IssueFilters
    ) -> tuple[int, str, int, int, str]:
        if not cursor or len(cursor) > 8192 or cursor.count(".") != 1:
            raise InvalidIssuesCursorError("cursor format is invalid")
        encoded_payload, encoded_signature = cursor.split(".")
        try:
            payload = _base64url_decode(encoded_payload)
            signature = _base64url_decode(encoded_signature)
            decoded = json.loads(payload)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidIssuesCursorError("cursor format is invalid") from exc
        expected_signature = hmac.new(self._cursor_secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise InvalidIssuesCursorError("cursor signature is invalid")
        if not isinstance(decoded, dict) or set(decoded) != {"v", "s", "f", "k"}:
            raise InvalidIssuesCursorError("cursor payload is invalid")
        key = decoded["k"]
        if (
            decoded["v"] != 1
            or decoded["s"] != scan_id
            or decoded["f"] != filters.cursor_payload()
            or not isinstance(key, list)
            or len(key) != 5
            or type(key[0]) is not int
            or not isinstance(key[1], str)
            or type(key[2]) is not int
            or type(key[3]) is not int
            or not isinstance(key[4], str)
        ):
            raise InvalidIssuesCursorError("cursor context is invalid")
        if not _is_valid_issue_position_key(tuple(key)):
            raise InvalidIssuesCursorError("cursor key is invalid")
        return cast(tuple[int, str, int, int, str], tuple(key))

    def claim_next_scan(
        self, worker_id: str, *, lease_seconds: int, max_attempts: int
    ) -> ClaimedScan | None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    WITH exhausted AS (
                        UPDATE scan_jobs
                        SET status = 'FAILED', updated_at = now()
                        WHERE status = 'RUNNING'
                          AND locked_at < now() - (%s * interval '1 second')
                          AND attempts >= %s
                        RETURNING scan_id
                    )
                    UPDATE scan_runs AS run
                    SET status = 'FAILED', phase = 'FAILED', progress_percent = NULL,
                        message = %s, error_code = 'WORKER_LEASE_EXHAUSTED',
                        archive_data = NULL, updated_at = now()
                    FROM exhausted
                    WHERE run.id = exhausted.scan_id
                    """,
                    (
                        lease_seconds,
                        max_attempts,
                        "분석 Worker 복구 시도 횟수를 초과했습니다. 다시 실행해 주세요.",
                    ),
                )
                cursor.execute(
                    """
                    WITH retryable AS (
                        UPDATE scan_jobs
                        SET status = 'PENDING', worker_id = NULL, locked_at = NULL,
                            updated_at = now()
                        WHERE status = 'RUNNING'
                          AND locked_at < now() - (%s * interval '1 second')
                          AND attempts < %s
                        RETURNING scan_id
                    )
                    UPDATE scan_runs AS run
                    SET status = 'PENDING', phase = 'PENDING', progress_percent = NULL,
                        completed_units = 0, total_units = NULL, error_code = NULL,
                        message = %s, updated_at = now()
                    FROM retryable
                    WHERE run.id = retryable.scan_id
                    """,
                    (
                        lease_seconds,
                        max_attempts,
                        "중단된 분석 작업을 안전하게 다시 대기열에 등록했습니다.",
                    ),
                )
                cursor.execute(
                    """
                    WITH picked AS (
                        SELECT scan_id FROM scan_jobs
                        WHERE status = 'PENDING'
                        ORDER BY created_at
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    ), claimed AS (
                        UPDATE scan_jobs AS job
                        SET status = 'RUNNING', worker_id = %s, attempts = attempts + 1,
                            locked_at = now(), updated_at = now()
                        FROM picked
                        WHERE job.scan_id = picked.scan_id
                        RETURNING job.scan_id, job.worker_id, job.attempts
                    )
                    UPDATE scan_runs AS run
                    SET status = 'RUNNING', phase = 'ZIP_VALIDATION',
                        progress_percent = NULL, completed_units = 0, total_units = NULL,
                        message = %s, updated_at = now()
                    FROM claimed
                    WHERE run.id = claimed.scan_id
                    RETURNING run.id::text AS scan_id, run.project_id, run.archive_data,
                              claimed.worker_id, claimed.attempts
                    """,
                    (worker_id, "ZIP 파일의 안전성을 검사하고 있습니다."),
                )
                row = cursor.fetchone()
        if not row:
            return None
        if row["archive_data"] is None:
            raise RuntimeError("claimed scan has no archive data")
        return ClaimedScan.model_validate(row)

    def is_scan_workspace_reapable(self, scan_id: str) -> bool:
        """Return true only for scans whose run and job are both terminal.

        A terminal job cannot carry an active lease. Keeping both state machines in
        the predicate prevents the filesystem janitor from deleting a pending or
        running attempt workspace based on only one stale record.
        """
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT (
                        EXISTS (
                            SELECT 1 FROM scan_runs AS run
                            JOIN scan_jobs AS job ON job.scan_id = run.id
                            WHERE run.id = %s AND (
                                (run.status = 'COMPLETED' AND job.status = 'COMPLETED')
                                OR (run.status = 'FAILED' AND job.status = 'FAILED')
                            )
                        ) OR EXISTS (
                            SELECT 1 FROM deleted_scan_workspaces WHERE scan_id = %s
                        )
                    ) AS reapable
                    """,
                    (scan_id, scan_id),
                )
                row = cursor.fetchone()
        return bool(row and row["reapable"] is True)

    def clear_deleted_scan_workspace(self, scan_id: str) -> None:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM deleted_scan_workspaces WHERE scan_id = %s",
                    (scan_id,),
                )

    def list_deleted_scan_workspaces(self) -> list[str]:
        self.ensure_schema()
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT scan_id::text AS scan_id FROM deleted_scan_workspaces")
                rows = cursor.fetchall()
        return [str(row["scan_id"]) for row in rows]

    def update_progress(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        phase: str,
        completed_units: int,
        total_units: int,
        message: str,
        detected_languages: Sequence[str] | None = None,
    ) -> None:
        if total_units <= 0 or completed_units < 0 or completed_units > total_units:
            raise ValueError("progress units must satisfy 0 <= completed <= total")
        percent = min(99, (completed_units * 100) // total_units)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_jobs
                    SET locked_at = now(), updated_at = now()
                    WHERE scan_id = %s AND status = 'RUNNING'
                      AND worker_id = %s AND attempts = %s
                    RETURNING scan_id
                    """,
                    (scan_id, worker_id, attempt),
                )
                if cursor.fetchone() is None:
                    raise StaleScanLeaseError("scan lease is no longer owned by this worker")
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET phase = %s, completed_units = %s, total_units = %s,
                        progress_percent = %s, message = %s,
                        detected_languages = COALESCE(%s, detected_languages),
                        updated_at = now()
                    WHERE id = %s AND status = 'RUNNING'
                      AND completed_units <= %s
                      AND (total_units IS NULL OR total_units = %s)
                    """,
                    (
                        phase,
                        completed_units,
                        total_units,
                        percent,
                        message,
                        Jsonb(list(detected_languages)) if detected_languages is not None else None,
                        scan_id,
                        completed_units,
                        total_units,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StaleScanLeaseError(
                        "running scan no longer accepts non-monotonic progress"
                    )

    def renew_scan_lease(self, scan_id: str, *, worker_id: str, attempt: int) -> None:
        """Refresh ownership while a long-running analyzer subprocess is active."""
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_jobs
                    SET locked_at = now(), updated_at = now()
                    WHERE scan_id = %s AND status = 'RUNNING'
                      AND worker_id = %s AND attempts = %s
                    RETURNING scan_id
                    """,
                    (scan_id, worker_id, attempt),
                )
                if cursor.fetchone() is None:
                    raise StaleScanLeaseError("scan lease is no longer owned by this worker")

    def record_engine_snapshot(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        engine_name: str,
        engine_version: str,
        rulepack_name: str,
        rulepack_manifest: RulepackManifest,
    ) -> None:
        registered_rule_count = len(rulepack_manifest.rule_ids)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_runs AS run
                    SET engine_name = COALESCE(run.engine_name, %s),
                        engine_version = COALESCE(run.engine_version, %s),
                        rulepack_name = COALESCE(run.rulepack_name, %s),
                        rulepack_version = COALESCE(run.rulepack_version, %s),
                        ruleset_digest = COALESCE(run.ruleset_digest, %s),
                        registered_rule_count = COALESCE(run.registered_rule_count, %s),
                        updated_at = now()
                    FROM scan_jobs AS job
                    WHERE run.id = %s AND run.status = 'RUNNING'
                      AND job.scan_id = run.id AND job.status = 'RUNNING'
                      AND job.worker_id = %s AND job.attempts = %s
                      AND (run.engine_name IS NULL OR run.engine_name = %s)
                      AND (run.engine_version IS NULL OR run.engine_version = %s)
                      AND (run.rulepack_name IS NULL OR run.rulepack_name = %s)
                      AND (run.rulepack_version IS NULL OR run.rulepack_version = %s)
                      AND (run.ruleset_digest IS NULL OR run.ruleset_digest = %s)
                      AND (run.registered_rule_count IS NULL OR run.registered_rule_count = %s)
                    """,
                    (
                        engine_name,
                        engine_version,
                        rulepack_name,
                        rulepack_manifest.version,
                        rulepack_manifest.digest,
                        registered_rule_count,
                        scan_id,
                        worker_id,
                        attempt,
                        engine_name,
                        engine_version,
                        rulepack_name,
                        rulepack_manifest.version,
                        rulepack_manifest.digest,
                        registered_rule_count,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ScanSnapshotConflictError(
                        "scan lease was lost or its immutable engine snapshot conflicts"
                    )

    def record_target_metadata(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        archive_file_count: int,
        analysis_file_count: int,
        detected_languages: Sequence[str],
        language_file_counts: dict[str, int],
        executed_rule_count: int,
    ) -> None:
        if type(archive_file_count) is not int or type(analysis_file_count) is not int:
            raise ValueError("archive and analysis file counts must be integers")
        if archive_file_count < analysis_file_count or analysis_file_count < 0:
            raise ValueError("archive and analysis file counts are inconsistent")
        supported_languages = {"Java", "JavaScript", "Python"}
        detected_language_set = set(detected_languages)
        if len(detected_language_set) != len(detected_languages):
            raise ValueError("detected languages must not contain duplicates")
        if not detected_language_set <= supported_languages:
            raise ValueError("detected languages must use supported language names")
        if not set(language_file_counts) <= supported_languages:
            raise ValueError("language file counts must use supported language names")
        if any(type(count) is not int or count <= 0 for count in language_file_counts.values()):
            raise ValueError("language file counts must be positive integers")
        if set(language_file_counts) != detected_language_set:
            raise ValueError("language file counts must match detected languages")
        if sum(language_file_counts.values()) != analysis_file_count:
            raise ValueError("language file counts must sum to analysis file count")
        if type(executed_rule_count) is not int or executed_rule_count < 0:
            raise ValueError("executed rule count must be a non-negative integer")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_runs AS run
                    SET archive_file_count = COALESCE(run.archive_file_count, %s),
                        analysis_file_count = COALESCE(run.analysis_file_count, %s),
                        detected_languages = %s,
                        language_file_counts = %s,
                        supported_rule_count = COALESCE(run.supported_rule_count, %s),
                        updated_at = now()
                    FROM scan_jobs AS job
                    WHERE run.id = %s AND run.status = 'RUNNING'
                      AND job.scan_id = run.id AND job.status = 'RUNNING'
                      AND job.worker_id = %s AND job.attempts = %s
                      AND (run.archive_file_count IS NULL OR run.archive_file_count = %s)
                      AND (run.analysis_file_count IS NULL OR run.analysis_file_count = %s)
                      AND (run.supported_rule_count IS NULL OR run.supported_rule_count = %s)
                      AND (run.detected_languages = '[]'::jsonb OR run.detected_languages = %s)
                      AND (run.language_file_counts = '{}'::jsonb OR run.language_file_counts = %s)
                    """,
                    (
                        archive_file_count,
                        analysis_file_count,
                        Jsonb(list(detected_languages)),
                        Jsonb(language_file_counts),
                        executed_rule_count,
                        scan_id,
                        worker_id,
                        attempt,
                        archive_file_count,
                        analysis_file_count,
                        executed_rule_count,
                        Jsonb(list(detected_languages)),
                        Jsonb(language_file_counts),
                    ),
                )
                if cursor.rowcount != 1:
                    raise ScanSnapshotConflictError(
                        "scan lease was lost or its immutable target metadata conflicts"
                    )

    def complete_scan(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        detected_languages: Sequence[str],
        results: Sequence[JsonObject],
        language_results: Sequence[LanguageCoverageResult] | None = None,
        rulepack_manifest: RulepackManifest,
        issues: Sequence[NormalizedIssue] = (),
        manifest_nodes: Sequence[ScanFileNode] = (),
        completion_message: str = "분석이 완료되었습니다.",
    ) -> None:
        completion_message = completion_message.strip()
        if not completion_message or len(completion_message) > 4000:
            raise ValueError("completion message must contain 1 to 4000 characters")
        try:
            result_ids = [str(item["weakness_id"]) for item in results]
        except KeyError as exc:
            raise ValueError("every weakness result must have a weakness_id") from exc
        if tuple(result_ids) != EXPECTED_WEAKNESS_ID_SEQUENCE:
            raise ValueError(
                "a completed scan must contain each of the 49 weaknesses exactly once in order"
            )
        validated_results = _validate_complete_results(results, detected_languages)
        validated_language_results = _validate_complete_language_results(
            language_results
            if language_results is not None
            else _language_results_from_legacy_results(validated_results, detected_languages),
            detected_languages,
        )
        validated_issues = _validate_complete_issues_v2(
            issues, validated_language_results, detected_languages
        )
        manifest_summary = validate_scan_file_manifest(
            manifest_nodes, finding_paths=[issue.path for issue in validated_issues]
        )
        if tuple(detected_languages) != manifest_summary.detected_languages:
            raise ValueError("detected languages must match TARGET manifest files")
        rule_count_snapshot = supported_rule_count(detected_languages, rulepack_manifest)
        issue_stats = _issue_stats_from_issues(validated_issues)
        issue_counts_by_weakness = dict(sorted(_issue_counts_by_weakness(validated_issues).items()))
        guidance_by_fingerprint = {
            issue.fingerprint: _issue_guidance_snapshot(issue) for issue in validated_issues
        }
        manifest_root_count = sum(node.parent_path is None for node in manifest_nodes)
        manifest_directory_count = sum(
            node.entry_type is ScanFileType.DIRECTORY for node in manifest_nodes
        )
        manifest_finding_count = sum(
            node.finding_count for node in manifest_nodes if node.entry_type is ScanFileType.FILE
        )
        if manifest_finding_count != issue_stats.total_issue_count:
            raise ValueError("manifest and issue finding counts must match")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        run.archive_file_count, run.analysis_file_count,
                        run.detected_languages, run.language_file_counts,
                        run.engine_name, run.engine_version, run.rulepack_name,
                        run.rulepack_version, run.ruleset_digest,
                        run.registered_rule_count, run.supported_rule_count,
                        run.total_units, run.completed_units, run.archive_data,
                        run.manifest_version, run.manifest_node_count,
                        run.issue_model_version, run.manifest_summary_version,
                        run.issue_summary_version, run.language_coverage_result_count
                    FROM scan_runs AS run
                    JOIN scan_jobs AS job ON job.scan_id = run.id
                    WHERE run.id = %s AND run.status = 'RUNNING'
                      AND job.status = 'RUNNING' AND job.worker_id = %s
                      AND job.attempts = %s
                    FOR UPDATE OF run, job
                    """,
                    (scan_id, worker_id, attempt),
                )
                snapshot = cursor.fetchone()
                if snapshot is None:
                    raise StaleScanLeaseError("scan lease is no longer owned by this worker")
                _validate_completion_snapshot(
                    snapshot,
                    manifest_summary=manifest_summary,
                    detected_languages=detected_languages,
                    rulepack_manifest=rulepack_manifest,
                    rule_count_snapshot=rule_count_snapshot,
                )
                cursor.execute(
                    """
                    SELECT
                        EXISTS (
                            SELECT 1 FROM scan_weakness_results WHERE scan_id = %s
                        ) AS has_results,
                        EXISTS (
                            SELECT 1 FROM scan_files WHERE scan_id = %s
                        ) AS has_manifest,
                        EXISTS (
                            SELECT 1 FROM scan_issues WHERE scan_id = %s
                        ) AS has_issues,
                        EXISTS (
                            SELECT 1 FROM scan_language_results WHERE scan_id = %s
                        ) AS has_language_results
                    """,
                    (scan_id, scan_id, scan_id, scan_id),
                )
                existing = cursor.fetchone()
                if (
                    existing is None
                    or existing["has_results"]
                    or existing["has_manifest"]
                    or existing.get("has_issues", False)
                    or existing.get("has_language_results", False)
                ):
                    raise ScanSnapshotConflictError(
                        "completion requires an empty once-only persistence boundary"
                    )
                cursor.executemany(
                    """
                    INSERT INTO scan_weakness_results (scan_id, weakness_id, result)
                    VALUES (%s, %s, %s)
                    """,
                    [
                        (
                            scan_id,
                            item.weakness_id,
                            Jsonb(
                                CoverageCriterionSnapshot(
                                    weakness_id=item.weakness_id,
                                    number=item.number,
                                    category=item.category,
                                    category_number=item.category_number,
                                    name=item.name,
                                    description=item.description,
                                    sast_classification=item.sast_classification,
                                    implementation_status=item.implementation_status,
                                ).model_dump(mode="json")
                            ),
                        )
                        for item in validated_results
                    ],
                )
                if validated_language_results:
                    cursor.executemany(
                        """
                        INSERT INTO scan_language_results (
                            scan_id, weakness_id, weakness_number, language,
                            support_status, result_status, executed_rule_count,
                            finding_count, reason
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        [
                            (
                                scan_id,
                                f"KISA-2021-{weakness_number:02d}",
                                weakness_number,
                                item.language,
                                item.support_status.value,
                                item.result_status.value,
                                item.executed_rule_count,
                                item.finding_count,
                                item.reason,
                            )
                            for weakness_number, item in _numbered_language_results(
                                validated_language_results, detected_languages
                            )
                        ],
                    )
                cursor.executemany(
                    """
                    INSERT INTO scan_files (
                        scan_id, path, parent_path, depth, node_type, size,
                        language, state, finding_count
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            scan_id,
                            node.path,
                            node.parent_path,
                            node.depth,
                            node.entry_type.value,
                            node.size_bytes or 0,
                            node.language,
                            node.analysis_state.value,
                            node.finding_count,
                        )
                        for node in manifest_nodes
                    ],
                )
                if validated_issues:
                    cursor.executemany(
                        """
                        INSERT INTO scan_issues (
                            issue_id, scan_id, fingerprint, fingerprint_version,
                            result_status, finding_kind, detection_basis_version,
                            confidence, detection_rationale, severity,
                            weakness_id, weakness_number, weakness_name,
                            weakness_category, weakness_category_number,
                            weakness_description, sast_classification,
                            implementation_status, rule_id, language, path,
                            start_line, start_column, end_line, end_column,
                            message, rule_description, cwe_id,
                            guidance_version, automation_limitation,
                            manual_verification_checks, remediation,
                            safe_implementation_example, guidance_references
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s
                        )
                        """,
                        [
                            (
                                issue_id_for(scan_id, issue.fingerprint),
                                scan_id,
                                issue.fingerprint,
                                issue.fingerprint_version,
                                issue.result_status.value,
                                issue.finding_kind.value,
                                issue.detection_basis_version,
                                issue.confidence.value,
                                issue.detection_rationale,
                                issue.severity.value,
                                issue.weakness_id,
                                issue.weakness_number,
                                issue.weakness_name,
                                issue.weakness_category,
                                issue.weakness_category_number,
                                issue.weakness_description,
                                issue.sast_classification,
                                issue.implementation_status.value,
                                issue.rule_id,
                                issue.language,
                                issue.path,
                                issue.start_line,
                                issue.start_column,
                                issue.end_line,
                                issue.end_column,
                                issue.message,
                                issue.rule_description,
                                issue.cwe_id,
                                ISSUE_GUIDANCE_VERSION,
                                guidance_by_fingerprint[issue.fingerprint].automation_limitation,
                                Jsonb(
                                    list(
                                        guidance_by_fingerprint[
                                            issue.fingerprint
                                        ].manual_verification_checks
                                    )
                                ),
                                guidance_by_fingerprint[issue.fingerprint].remediation,
                                guidance_by_fingerprint[
                                    issue.fingerprint
                                ].safe_implementation_example,
                                Jsonb(list(guidance_by_fingerprint[issue.fingerprint].references)),
                            )
                            for issue in validated_issues
                        ],
                    )
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET status = 'COMPLETED', phase = 'COMPLETED', progress_percent = 100,
                        completed_units = total_units, message = %s,
                        detected_languages = %s, supported_rule_count = %s,
                        rulepack_version = %s, manifest_version = %s,
                        manifest_node_count = %s, issue_model_version = %s,
                        manifest_summary_version = %s, manifest_root_count = %s,
                        manifest_directory_count = %s, manifest_file_count = %s,
                        manifest_finding_count = %s,
                        issue_summary_version = %s, coverage_result_count = %s,
                        issue_count = %s, detected_issue_count = %s,
                        review_signal_count = %s, issue_error_count = %s,
                        issue_warning_count = %s, issue_info_count = %s,
                        issue_counts_by_weakness = %s,
                        language_coverage_result_count = %s,
                        archive_data = NULL, updated_at = now()
                    WHERE id = %s AND status = 'RUNNING'
                      AND total_units IS NOT NULL AND completed_units <= total_units
                      AND engine_name IS NOT NULL AND engine_version IS NOT NULL
                      AND rulepack_name IS NOT NULL AND ruleset_digest IS NOT NULL
                      AND registered_rule_count IS NOT NULL
                      AND supported_rule_count = %s
                    """,
                    (
                        completion_message,
                        Jsonb(list(detected_languages)),
                        rule_count_snapshot,
                        RULEPACK_VERSION,
                        MANIFEST_VERSION,
                        manifest_summary.node_count,
                        ISSUE_MODEL_VERSION,
                        SNAPSHOT_SUMMARY_VERSION,
                        manifest_root_count,
                        manifest_directory_count,
                        manifest_summary.archive_file_count,
                        manifest_finding_count,
                        ISSUE_SNAPSHOT_SUMMARY_VERSION,
                        len(KISA_CATALOG),
                        issue_stats.total_issue_count,
                        issue_stats.detected_issue_count,
                        issue_stats.review_signal_count,
                        issue_stats.severity_counts.error,
                        issue_stats.severity_counts.warning,
                        issue_stats.severity_counts.info,
                        Jsonb(issue_counts_by_weakness),
                        len(validated_language_results),
                        scan_id,
                        rule_count_snapshot,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StaleScanLeaseError("running scan no longer accepts completion")
                cursor.execute(
                    """
                    UPDATE scan_jobs
                    SET status = 'COMPLETED', locked_at = now(), updated_at = now()
                    WHERE scan_id = %s AND status = 'RUNNING'
                      AND worker_id = %s AND attempts = %s
                    """,
                    (scan_id, worker_id, attempt),
                )
                if cursor.rowcount != 1:
                    raise StaleScanLeaseError("scan lease was lost before completion")

    def fail_scan(
        self,
        scan_id: str,
        *,
        worker_id: str,
        attempt: int,
        error_code: str,
        message: str,
    ) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scan_jobs
                    SET locked_at = now(), updated_at = now()
                    WHERE scan_id = %s AND status = 'RUNNING'
                      AND worker_id = %s AND attempts = %s
                    RETURNING scan_id
                    """,
                    (scan_id, worker_id, attempt),
                )
                if cursor.fetchone() is None:
                    raise StaleScanLeaseError("scan lease is no longer owned by this worker")
                cursor.execute(
                    """
                    UPDATE scan_runs
                    SET status = 'FAILED', phase = 'FAILED', progress_percent = NULL,
                        message = %s, error_code = %s, archive_data = NULL, updated_at = now()
                    WHERE id = %s AND status = 'RUNNING'
                    """,
                    (message, error_code, scan_id),
                )
                if cursor.rowcount != 1:
                    raise StaleScanLeaseError("running scan no longer accepts failure")
                cursor.execute(
                    """
                    UPDATE scan_jobs SET status = 'FAILED', updated_at = now()
                    WHERE scan_id = %s AND status = 'RUNNING'
                      AND worker_id = %s AND attempts = %s
                    """,
                    (scan_id, worker_id, attempt),
                )
                if cursor.rowcount != 1:
                    raise StaleScanLeaseError("scan lease was lost before failure")


def _validate_complete_issues(
    issues: Sequence[NormalizedIssue],
    results: Sequence[WeaknessResult],
    detected_languages: Sequence[str],
) -> list[NormalizedIssue]:
    validated = [NormalizedIssue.model_validate(issue) for issue in issues]
    if len({issue.fingerprint for issue in validated}) != len(validated):
        raise ValueError("normalized issue fingerprints must be unique")
    present_languages = set(detected_languages)
    for issue in validated:
        _validate_current_issue_metadata(issue)
        if issue.language not in present_languages:
            raise ValueError("issue language must be present in detected_languages")
        expected_fingerprint = issue_fingerprint(
            rule_id=issue.rule_id,
            finding_kind=issue.finding_kind,
            language=issue.language,
            path=issue.path,
            start_line=issue.start_line,
            start_column=issue.start_column,
            end_line=issue.end_line,
            end_column=issue.end_column,
        )
        if issue.fingerprint != expected_fingerprint:
            raise ValueError("issue fingerprint does not match its canonical fields")

    persisted_finding_keys = Counter(
        (
            issue.rule_id,
            issue.finding_kind.value,
            issue.language,
            issue.path,
            issue.start_line,
            issue.message,
            issue.severity.value,
        )
        for issue in validated
    )
    result_finding_keys = Counter(
        (
            finding.rule_id,
            finding.kind.value if finding.kind is not None else None,
            finding.language,
            finding.path,
            finding.start_line,
            finding.message,
            finding.severity,
        )
        for result in results
        for finding in result.findings
    )
    if persisted_finding_keys != result_finding_keys:
        raise ValueError("normalized issues must exactly match the 49-result findings")
    _validate_issue_coverage_relationship(
        [
            CoverageResult.model_validate(
                {
                    key: value
                    for key, value in item.model_dump(mode="json").items()
                    if key not in {"findings", "finding_count"}
                }
            )
            for item in results
        ],
        validated,
    )
    return sorted(
        validated,
        key=lambda issue: (
            issue.weakness_number,
            issue.path.encode("utf-8"),
            issue.start_line,
            issue.start_column,
            issue.fingerprint,
        ),
    )


def _numbered_language_results(
    results: Sequence[LanguageCoverageResult], detected_languages: Sequence[str]
) -> list[tuple[int, LanguageCoverageResult]]:
    language_count = len(detected_languages)
    if language_count == 0:
        return []
    return [(index // language_count + 1, item) for index, item in enumerate(results)]


def _validate_complete_language_results(
    results: Sequence[LanguageCoverageResult], detected_languages: Sequence[str]
) -> list[LanguageCoverageResult]:
    languages = tuple(detected_languages)
    if len(set(languages)) != len(languages) or not set(languages) <= {
        "Java",
        "JavaScript",
        "Python",
    }:
        raise ValueError("detected_languages must contain unique supported language names")
    validated = [LanguageCoverageResult.model_validate(item) for item in results]
    if len(validated) != len(KISA_CATALOG) * len(languages):
        raise ValueError("v2 coverage requires 49 rows for every detected language")
    for index, item in enumerate(validated):
        weakness_number = index // len(languages) + 1
        language = languages[index % len(languages)]
        if item.language != language:
            raise ValueError("v2 coverage language rows must use criterion-major order")
        rule_ids = VERIFIED_RULE_SUPPORT_MATRIX[(weakness_number, language)]
        if item.executed_rule_count != len(rule_ids):
            raise ValueError("v2 coverage executed rule count does not match verified registry")
        if bool(rule_ids) != (item.support_status.value == "SUPPORTED"):
            raise ValueError("v2 coverage support state does not match verified registry")
    return validated


def _language_results_from_legacy_results(
    results: Sequence[WeaknessResult], detected_languages: Sequence[str]
) -> list[LanguageCoverageResult]:
    findings = Counter(
        (result.number, finding.language)
        for result in results
        for finding in result.findings
        if finding.kind is FindingKind.DETECTED
    )
    normalized: list[LanguageCoverageResult] = []
    for weakness in KISA_CATALOG:
        for language in detected_languages:
            rule_ids = VERIFIED_RULE_SUPPORT_MATRIX[(weakness.number, language)]
            finding_count = findings[(weakness.number, language)]
            normalized.append(
                LanguageCoverageResult(
                    language=language,
                    support_status="SUPPORTED" if rule_ids else "NOT_SUPPORTED",
                    result_status=(
                        "DETECTED"
                        if finding_count
                        else "NOT_DETECTED"
                        if rule_ids
                        else "NOT_SUPPORTED"
                    ),
                    executed_rule_count=len(rule_ids),
                    finding_count=finding_count,
                    reason=(
                        "등록되고 검증된 자동 탐지 룰에서 코드 위치가 일치했습니다."
                        if finding_count
                        else "등록되고 검증된 자동 탐지 룰을 실행했으나 일치 항목이 없습니다."
                        if rule_ids
                        else "해당 기준·언어에 fixture로 검증된 자동 탐지 룰이 없습니다."
                    ),
                )
            )
    return normalized


def _validate_complete_issues_v2(
    issues: Sequence[NormalizedIssue],
    language_results: Sequence[LanguageCoverageResult],
    detected_languages: Sequence[str],
) -> list[NormalizedIssue]:
    validated = [NormalizedIssue.model_validate(issue) for issue in issues]
    if len({issue.fingerprint for issue in validated}) != len(validated):
        raise ValueError("normalized issue fingerprints must be unique")
    present_languages = set(detected_languages)
    counts: Counter[tuple[int, str]] = Counter()
    for issue in validated:
        _validate_current_issue_metadata(issue)
        registration = VERIFIED_DETECTED_RULE_REGISTRY.get(issue.rule_id)
        if (
            registration is None
            or issue.finding_kind is not FindingKind.DETECTED
            or issue.result_status is not ResultStatus.DETECTED
            or issue.language not in present_languages
        ):
            raise ValueError("issue model v2 stores verified DETECTED findings only")
        if issue.fingerprint != issue_fingerprint(
            rule_id=issue.rule_id,
            finding_kind=issue.finding_kind,
            language=issue.language,
            path=issue.path,
            start_line=issue.start_line,
            start_column=issue.start_column,
            end_line=issue.end_line,
            end_column=issue.end_column,
        ):
            raise ValueError("issue fingerprint does not match its canonical fields")
        counts[(issue.weakness_number, issue.language)] += 1
    for weakness_number, item in _numbered_language_results(language_results, detected_languages):
        if item.finding_count != counts[(weakness_number, item.language)]:
            raise ValueError("v2 language coverage finding counts must match normalized issues")
    return sorted(
        validated,
        key=lambda issue: (
            issue.weakness_number,
            issue.path.encode("utf-8"),
            issue.start_line,
            issue.start_column,
            issue.fingerprint,
        ),
    )


def _validate_current_issue_metadata(issue: NormalizedIssue) -> None:
    _validate_intrinsic_issue_metadata(issue)
    registration = RULE_REGISTRY.get(issue.rule_id)
    weakness = CATALOG_BY_ID.get(issue.weakness_id)
    if registration is None or weakness is None:
        raise ValueError("issue references unknown rule or weakness metadata")
    expected_status = (
        ResultStatus.DETECTED
        if registration.finding_kind is FindingKind.DETECTED
        else ResultStatus.REVIEW_REQUIRED
    )
    expected_metadata = (
        registration.weakness_number,
        registration.language,
        registration.finding_kind,
        weakness.number,
        weakness.name,
        weakness.category,
        weakness.category_number,
        weakness.description,
        weakness.sast_classification,
        weakness.implementation_status,
        expected_status,
    )
    actual_metadata = (
        issue.weakness_number,
        issue.language,
        issue.finding_kind,
        issue.weakness_number,
        issue.weakness_name,
        issue.weakness_category,
        issue.weakness_category_number,
        issue.weakness_description,
        issue.sast_classification,
        issue.implementation_status,
        issue.result_status,
    )
    if actual_metadata != expected_metadata:
        raise ValueError("issue rule, weakness, kind, or result metadata is inconsistent")
    expected_confidence, expected_rationale = issue_detection_snapshot(
        finding_kind=issue.finding_kind,
        rule_id=issue.rule_id,
        rule_description=issue.rule_description,
        message=issue.message,
    )
    if (
        issue.detection_basis_version != 1
        or issue.confidence is not expected_confidence
        or issue.detection_rationale != expected_rationale
    ):
        raise ValueError("issue detection basis does not match the current generator")


def _validate_intrinsic_issue_metadata(issue: NormalizedIssue) -> None:
    if issue.weakness_id != f"KISA-2021-{issue.weakness_number:02d}":
        raise ValueError("issue weakness ID and number are inconsistent")
    if issue.language not in {"Java", "JavaScript", "Python"}:
        raise ValueError("issue language is unsupported by model v1")
    bounded_text = (
        issue.weakness_name,
        issue.weakness_category,
        issue.weakness_description,
        issue.sast_classification,
        issue.rule_id,
    )
    if any(not value or len(value) > 4000 for value in bounded_text):
        raise ValueError("issue snapshot text is outside bounded limits")
    if issue.rule_description is not None and not 1 <= len(issue.rule_description) <= 4000:
        raise ValueError("issue rule description is outside bounded limits")
    try:
        if normalize_archive_path(issue.path) != issue.path:
            raise ValueError("issue path is not normalized")
    except UnsafeArchiveError as exc:
        raise ValueError("issue path is not a safe normalized relative path") from exc
    if issue.cwe_id is not None and CWE_ID_PATTERN.fullmatch(issue.cwe_id) is None:
        raise ValueError("issue CWE ID is not canonical")


def _issue_guidance_snapshot(issue: NormalizedIssue) -> _IssueGuidanceSnapshot:
    detected = issue.finding_kind is FindingKind.DETECTED
    remediation = (
        f"현재 규칙 신호: {issue.message} "
        "신뢰되지 않은 값을 보안 민감 연산에 직접 전달하지 말고, 업무에 맞는 허용 목록 "
        "검증과 안전한 전용 API를 경계에서 적용합니다."
    )[:4000]
    return _IssueGuidanceSnapshot(
        automation_limitation=(
            DETECTED_AUTOMATION_LIMITATION if detected else REVIEW_SIGNAL_AUTOMATION_LIMITATION
        ),
        manual_verification_checks=(
            DETECTED_MANUAL_CHECKS if detected else REVIEW_SIGNAL_MANUAL_CHECKS
        ),
        remediation=remediation,
        safe_implementation_example=SAFE_EXAMPLES[issue.language],
        references=_current_issue_guidance_references(issue),
    )


def _current_issue_guidance_references(issue: NormalizedIssue) -> tuple[str, ...]:
    if issue.cwe_id is None:
        return (CWE_INDEX_URL,)
    cwe_number = issue.cwe_id.removeprefix("CWE-")
    return (f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",)


def _validate_issue_guidance_row(
    row: dict[str, Any],
    issue: NormalizedIssue,
    *,
    guidance_version: int,
    cwe_index_url: str,
    cwe_definition_url_template: str,
) -> _IssueGuidanceSnapshot:
    if row.get("guidance_version") != guidance_version:
        raise ValueError("issue guidance version is missing")
    actual_checks = row.get("manual_verification_checks")
    actual_references = row.get("guidance_references")
    text_values = (
        row.get("automation_limitation"),
        row.get("remediation"),
        row.get("safe_implementation_example"),
    )
    if (
        not all(isinstance(value, str) for value in text_values)
        or not isinstance(actual_checks, list)
        or not all(isinstance(item, str) for item in actual_checks)
        or not isinstance(actual_references, list)
        or not all(isinstance(item, str) for item in actual_references)
    ):
        raise ValueError("issue guidance arrays are invalid")
    actual = _IssueGuidanceSnapshot(
        automation_limitation=cast(str, text_values[0]),
        manual_verification_checks=tuple(actual_checks),
        remediation=cast(str, text_values[1]),
        safe_implementation_example=cast(str, text_values[2]),
        references=tuple(actual_references),
    )
    if (
        any(
            not value or len(value) > 4000
            for value in (
                actual.automation_limitation,
                actual.remediation,
                actual.safe_implementation_example,
            )
        )
        or not 1 <= len(actual.manual_verification_checks) <= 5
        or any(not value or len(value) > 1000 for value in actual.manual_verification_checks)
    ):
        raise ValueError("issue guidance text is outside bounded limits")
    expected_references = (
        (cwe_definition_url_template.format(number=issue.cwe_id.removeprefix("CWE-")),)
        if issue.cwe_id is not None
        else (cwe_index_url,)
    )
    if actual.references != expected_references or any(
        not reference.startswith("https://") or len(reference) > 1000
        for reference in actual.references
    ):
        raise ValueError("issue guidance references do not match the persisted CWE")
    return actual


def _validate_stored_coverage(results: Sequence[JsonObject]) -> list[CoverageResult]:
    expected_keys = set(CoverageResult.model_fields)
    if any(set(result) != expected_keys for result in results):
        raise ValueError("coverage rows must not persist finding payloads or unknown fields")
    validated = [CoverageResult.model_validate(item) for item in results]
    if tuple(item.weakness_id for item in validated) != CANONICAL_WEAKNESS_ID_SEQUENCE:
        raise ValueError("stored coverage must contain all 49 canonical weaknesses")
    if tuple(item.number for item in validated) != tuple(range(1, 50)):
        raise ValueError("stored coverage numbers must remain canonical")
    for item in validated:
        _validate_intrinsic_coverage_item(item)
    return validated


def _validate_stored_criterion_snapshots(
    results: Sequence[JsonObject],
) -> list[CoverageCriterionSnapshot]:
    expected_keys = set(CoverageCriterionSnapshot.model_fields)
    if any(set(result) != expected_keys for result in results):
        raise ValueError("v2 criterion snapshots contain unknown or missing fields")
    validated = [CoverageCriterionSnapshot.model_validate(item) for item in results]
    if tuple(item.weakness_id for item in validated) != CANONICAL_WEAKNESS_ID_SEQUENCE:
        raise ValueError("v2 criterion snapshots must contain all canonical weaknesses")
    if tuple(item.number for item in validated) != tuple(range(1, 50)):
        raise ValueError("v2 criterion snapshot numbers must remain canonical")
    for item in validated:
        weakness = CATALOG_BY_ID[item.weakness_id]
        if (
            item.number,
            item.category,
            item.category_number,
            item.name,
            item.description,
            item.sast_classification,
            item.implementation_status,
        ) != (
            weakness.number,
            weakness.category,
            weakness.category_number,
            weakness.name,
            weakness.description,
            weakness.sast_classification,
            weakness.implementation_status,
        ):
            raise ValueError("v2 criterion metadata does not match the registered catalog")
    return validated


def _validate_stored_language_results(
    rows: Sequence[dict[str, Any]], detected_languages: Sequence[str]
) -> list[LanguageCoverageResult]:
    languages = tuple(detected_languages)
    language_rank = {language: index for index, language in enumerate(languages)}
    expected_keys = {
        "weakness_id",
        "weakness_number",
        "language",
        "support_status",
        "result_status",
        "executed_rule_count",
        "finding_count",
        "reason",
    }
    if any(set(row) != expected_keys for row in rows):
        raise ValueError("v2 language rows contain unknown or missing fields")
    ordered = sorted(
        rows,
        key=lambda row: (int(row["weakness_number"]), language_rank.get(row["language"], 999)),
    )
    validated: list[LanguageCoverageResult] = []
    for row in ordered:
        weakness_number = row["weakness_number"]
        if row["weakness_id"] != f"KISA-2021-{weakness_number:02d}":
            raise ValueError("v2 language row weakness identity is inconsistent")
        validated.append(
            LanguageCoverageResult.model_validate(
                {key: row[key] for key in LanguageCoverageResult.model_fields}
            )
        )
    return _validate_complete_language_results(validated, languages)


def _coverage_items_v2(
    criteria: Sequence[CoverageCriterionSnapshot],
    language_results: Sequence[LanguageCoverageResult],
    detected_languages: Sequence[str],
) -> list[CoverageCriterionV2]:
    language_count = len(detected_languages)
    items: list[CoverageCriterionV2] = []
    for index, criterion in enumerate(criteria):
        start = index * language_count
        rows = list(language_results[start : start + language_count])
        items.append(
            CoverageCriterionV2(
                **criterion.model_dump(mode="json"),
                reason="분석 대상 언어별 자동 탐지 결과를 확인하세요.",
                finding_count=sum(item.finding_count for item in rows),
                languages=rows,
            )
        )
    return items


def _validate_v2_coverage_issue_relationship(
    items: Sequence[CoverageCriterionV2], counts_by_weakness: dict[str, int]
) -> None:
    for item in items:
        if item.finding_count != counts_by_weakness.get(item.weakness_id, 0):
            raise ValueError("v2 criterion finding count does not match persisted issues")


def _validate_intrinsic_coverage_item(item: CoverageResult) -> None:
    text_values = (
        item.category,
        item.name,
        item.description,
        item.sast_classification,
        item.reason,
    )
    if any(not isinstance(value, str) or not value or len(value) > 4000 for value in text_values):
        raise ValueError("stored coverage text is outside bounded limits")
    if item.category_number > 49 or item.sast_classification not in {
        "AUTO",
        "PARTIAL",
        "MANUAL",
    }:
        raise ValueError("stored coverage classification is invalid")
    if item.implementation_status is None:
        raise ValueError("issue model v1 coverage requires implementation status")
    state = (
        item.implementation_status.value,
        item.support_status.value,
        item.result_status.value,
    )
    allowed_states = {
        ("IMPLEMENTED", "SUPPORTED", "DETECTED"),
        ("IMPLEMENTED", "SUPPORTED", "NOT_DETECTED"),
        ("IMPLEMENTED", "NOT_SUPPORTED", "NOT_SUPPORTED"),
        ("PARTIALLY_IMPLEMENTED", "PARTIALLY_SUPPORTED", "DETECTED"),
        ("PARTIALLY_IMPLEMENTED", "PARTIALLY_SUPPORTED", "REVIEW_REQUIRED"),
        ("PARTIALLY_IMPLEMENTED", "NOT_SUPPORTED", "NOT_SUPPORTED"),
        ("MANUAL_REVIEW_REQUIRED", "MANUAL_REVIEW_REQUIRED", "REVIEW_REQUIRED"),
        ("NOT_IMPLEMENTED", "NOT_SUPPORTED", "NOT_SUPPORTED"),
    }
    if state not in allowed_states:
        raise ValueError("stored coverage state is internally inconsistent")


def _validate_stored_issues(rows: Sequence[dict[str, Any]]) -> list[NormalizedIssue]:
    validated: list[NormalizedIssue] = []
    seen: set[str] = set()
    for row in rows:
        issue = _normalized_issue_from_row(row)
        _validate_intrinsic_issue_metadata(issue)
        if issue.fingerprint in seen:
            raise ValueError("stored issue fingerprints must be unique")
        seen.add(issue.fingerprint)
        if issue.fingerprint != issue_fingerprint(
            rule_id=issue.rule_id,
            finding_kind=issue.finding_kind,
            language=issue.language,
            path=issue.path,
            start_line=issue.start_line,
            start_column=issue.start_column,
            end_line=issue.end_line,
            end_column=issue.end_column,
        ):
            raise ValueError("stored issue fingerprint is invalid")
        scan_id = str(row.get("scan_id", ""))
        if str(row.get("issue_id", "")) != issue_id_for(scan_id, issue.fingerprint):
            raise ValueError("stored issue ID is invalid")
        validated.append(issue)
    return validated


def _normalized_issue_from_row(row: dict[str, Any]) -> NormalizedIssue:
    return NormalizedIssue.model_validate(
        {
            "fingerprint": row.get("fingerprint"),
            "fingerprint_version": row.get("fingerprint_version"),
            "result_status": row.get("result_status"),
            "finding_kind": row.get("finding_kind"),
            "detection_basis_version": row.get("detection_basis_version"),
            "confidence": row.get("confidence"),
            "detection_rationale": row.get("detection_rationale"),
            "severity": row.get("severity"),
            "weakness_id": row.get("weakness_id"),
            "weakness_number": row.get("weakness_number"),
            "weakness_name": row.get("weakness_name"),
            "weakness_category": row.get("weakness_category"),
            "weakness_category_number": row.get("weakness_category_number"),
            "weakness_description": row.get("weakness_description"),
            "sast_classification": row.get("sast_classification"),
            "implementation_status": row.get("implementation_status"),
            "rule_id": row.get("rule_id"),
            "language": row.get("language"),
            "path": row.get("path"),
            "start_line": row.get("start_line"),
            "start_column": row.get("start_column"),
            "end_line": row.get("end_line"),
            "end_column": row.get("end_column"),
            "message": row.get("message"),
            "rule_description": row.get("rule_description"),
            "cwe_id": row.get("cwe_id"),
        }
    )


def _validate_issue_coverage_relationship(
    coverage: Sequence[CoverageResult], issues: Sequence[NormalizedIssue]
) -> None:
    coverage_by_id = {item.weakness_id: item for item in coverage}
    counts = _issue_counts_by_weakness(issues)
    for issue in issues:
        item = coverage_by_id.get(issue.weakness_id)
        if item is None or issue.result_status is not item.result_status:
            raise ValueError("issue result status must match its coverage criterion")
    for item in coverage:
        finding_count = counts.get(item.weakness_id, 0)
        if item.result_status is ResultStatus.DETECTED and finding_count == 0:
            raise ValueError("DETECTED coverage requires at least one normalized issue")
        if item.result_status in {ResultStatus.NOT_DETECTED, ResultStatus.NOT_SUPPORTED} and (
            finding_count != 0
        ):
            raise ValueError("non-finding coverage cannot contain normalized issues")
        if (
            item.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED
            and item.result_status is not ResultStatus.REVIEW_REQUIRED
        ):
            raise ValueError("manual coverage must remain REVIEW_REQUIRED")


def _manifest_snapshot_summary_from_scan(
    scan: dict[str, Any],
) -> _ManifestSnapshotSummary:
    fields = (
        "manifest_node_count",
        "manifest_root_count",
        "manifest_directory_count",
        "manifest_file_count",
        "manifest_finding_count",
        "archive_file_count",
        "analysis_file_count",
    )
    if (
        scan.get("manifest_version") != MANIFEST_VERSION
        or scan.get("manifest_summary_version") != SNAPSHOT_SUMMARY_VERSION
        or any(type(scan.get(field)) is not int for field in fields)
    ):
        raise ValueError("manifest summary fields are incomplete")
    summary = _ManifestSnapshotSummary(
        node_count=scan["manifest_node_count"],
        root_count=scan["manifest_root_count"],
        directory_count=scan["manifest_directory_count"],
        file_count=scan["manifest_file_count"],
        finding_count=scan["manifest_finding_count"],
    )
    if (
        summary.node_count < 1
        or summary.node_count > 20_000
        or summary.root_count < 1
        or summary.root_count > summary.node_count
        or summary.directory_count < 0
        or summary.file_count < 0
        or summary.node_count != summary.directory_count + summary.file_count
        or summary.file_count != scan["archive_file_count"]
        or scan["analysis_file_count"] < 0
        or scan["analysis_file_count"] > summary.file_count
        or summary.finding_count < 0
        or summary.finding_count > 10_000
    ):
        raise ValueError("manifest summary fields are inconsistent")
    return summary


def _issue_snapshot_summary_from_scan(
    scan: dict[str, Any], *, issue_model_version: int, summary_version: int
) -> _IssueSnapshotSummary:
    count_fields = (
        "coverage_result_count",
        "issue_count",
        "detected_issue_count",
        "review_signal_count",
        "issue_error_count",
        "issue_warning_count",
        "issue_info_count",
    )
    if (
        scan.get("issue_model_version") != issue_model_version
        or scan.get("issue_summary_version") != summary_version
        or any(type(scan.get(field)) is not int for field in count_fields)
    ):
        raise ValueError("issue summary fields are incomplete")
    if scan["coverage_result_count"] != 49:
        raise ValueError("coverage summary must contain exactly 49 criteria")
    if issue_model_version == 2:
        languages = scan.get("detected_languages")
        if (
            not isinstance(languages, list)
            or len(set(languages)) != len(languages)
            or scan.get("language_coverage_result_count") != 49 * len(languages)
            or scan.get("review_signal_count") != 0
        ):
            raise ValueError("v2 language coverage summary is inconsistent")
    counts_payload = scan.get("issue_counts_by_weakness")
    if not isinstance(counts_payload, dict):
        raise ValueError("issue weakness counts must be an object")
    counts_by_weakness: dict[str, int] = {}
    for weakness_id, count in counts_payload.items():
        if (
            not isinstance(weakness_id, str)
            or weakness_id not in CANONICAL_WEAKNESS_IDS
            or type(count) is not int
            or count <= 0
        ):
            raise ValueError("issue weakness counts are invalid")
        counts_by_weakness[weakness_id] = count
    stats = IssueStats(
        total_issue_count=scan["issue_count"],
        detected_issue_count=scan["detected_issue_count"],
        review_signal_count=scan["review_signal_count"],
        severity_counts=IssueSeverityCounts(
            ERROR=scan["issue_error_count"],
            WARNING=scan["issue_warning_count"],
            INFO=scan["issue_info_count"],
        ),
    )
    try:
        _validate_issue_stats(stats)
    except CorruptScanIssueModelError as exc:
        raise ValueError("issue statistics are inconsistent") from exc
    if stats.total_issue_count > 10_000:
        raise ValueError("issue count exceeds the immutable snapshot limit")
    if sum(counts_by_weakness.values()) != stats.total_issue_count:
        raise ValueError("issue weakness counts do not match the global total")
    return _IssueSnapshotSummary(
        stats=stats,
        counts_by_weakness=counts_by_weakness,
    )


def _validate_coverage_count_relationship(
    coverage: Sequence[CoverageResult], counts_by_weakness: dict[str, int]
) -> None:
    for item in coverage:
        finding_count = counts_by_weakness.get(item.weakness_id, 0)
        if item.result_status is ResultStatus.DETECTED and finding_count == 0:
            raise ValueError("DETECTED coverage requires normalized issues")
        if (
            item.result_status
            in {
                ResultStatus.NOT_DETECTED,
                ResultStatus.NOT_SUPPORTED,
            }
            and finding_count != 0
        ):
            raise ValueError("non-finding coverage cannot contain normalized issues")
        if (
            item.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED
            and item.result_status is not ResultStatus.REVIEW_REQUIRED
        ):
            raise ValueError("manual coverage must remain REVIEW_REQUIRED")


def _issue_counts_by_weakness(
    issues: Sequence[NormalizedIssue],
) -> Counter[str]:
    return Counter(issue.weakness_id for issue in issues)


def _validate_complete_results(
    results: Sequence[JsonObject], detected_languages: Sequence[str]
) -> list[WeaknessResult]:
    present_languages = set(detected_languages)
    if len(present_languages) != len(detected_languages) or not present_languages <= {
        "Java",
        "JavaScript",
        "Python",
    }:
        raise ValueError("detected_languages must contain unique supported language names")
    validated = [WeaknessResult.model_validate(item) for item in results]
    if tuple(item.weakness_id for item in validated) != EXPECTED_WEAKNESS_ID_SEQUENCE:
        raise ValueError("completed results must contain all 49 weaknesses in catalog order")
    for item in validated:
        weakness = CATALOG_BY_ID[item.weakness_id]
        actual_metadata = (
            item.number,
            item.category,
            item.category_number,
            item.name,
            item.description,
            item.sast_classification,
            item.implementation_status,
        )
        expected_metadata = (
            weakness.number,
            weakness.category,
            weakness.category_number,
            weakness.name,
            weakness.description,
            weakness.sast_classification,
            weakness.implementation_status,
        )
        if actual_metadata != expected_metadata:
            raise ValueError(f"catalog metadata mismatch for {item.weakness_id}")
        if item.finding_count != len(item.findings):
            raise ValueError(f"finding_count mismatch for {item.weakness_id}")
        for finding in item.findings:
            registration = RULE_REGISTRY.get(finding.rule_id)
            if (
                registration is None
                or registration.weakness_number != item.number
                or registration.language != finding.language
                or registration.finding_kind is not finding.kind
            ):
                raise ValueError(f"finding rule metadata mismatch for {item.weakness_id}")
            if finding.language not in present_languages:
                raise ValueError(f"finding language mismatch for {item.weakness_id}")
            path = PurePosixPath(finding.path)
            if (
                not finding.path
                or "\\" in finding.path
                or path.is_absolute()
                or ".." in path.parts
                or path.as_posix() != finding.path
            ):
                raise ValueError(f"finding path must be workspace-relative for {item.weakness_id}")

    for item in validated:
        active_support = RULE_LANGUAGE_SUPPORT.get(item.number, frozenset()) & present_languages
        if item.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED:
            expected_state = ("MANUAL_REVIEW_REQUIRED", "REVIEW_REQUIRED")
        elif item.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED:
            if item.findings:
                expected_state = ("PARTIALLY_SUPPORTED", "DETECTED")
            elif active_support:
                expected_state = ("PARTIALLY_SUPPORTED", "REVIEW_REQUIRED")
            else:
                expected_state = ("NOT_SUPPORTED", "NOT_SUPPORTED")
        elif item.implementation_status is ImplementationStatus.IMPLEMENTED:
            if item.findings:
                expected_state = ("SUPPORTED", "DETECTED")
            elif active_support:
                expected_state = ("SUPPORTED", "NOT_DETECTED")
            else:
                expected_state = ("NOT_SUPPORTED", "NOT_SUPPORTED")
        else:
            expected_state = ("NOT_SUPPORTED", "NOT_SUPPORTED")
        actual_state = (item.support_status.value, item.result_status.value)
        if actual_state != expected_state:
            raise ValueError(f"invalid support/result state for {item.weakness_id}")
    return validated


def _validate_stored_results(results: Sequence[JsonObject]) -> list[WeaknessResult]:
    validated = [WeaknessResult.model_validate(item) for item in results]
    if tuple(item.weakness_id for item in validated) != CANONICAL_WEAKNESS_ID_SEQUENCE:
        raise ValueError("stored results must contain all 49 canonical weaknesses")
    if tuple(item.number for item in validated) != tuple(range(1, 50)):
        raise ValueError("stored result numbers must remain canonical")
    return validated


def _validate_completion_snapshot(
    snapshot: dict[str, Any],
    *,
    manifest_summary: ManifestSummary,
    detected_languages: Sequence[str],
    rulepack_manifest: RulepackManifest,
    rule_count_snapshot: int,
) -> None:
    expected = {
        "archive_file_count": manifest_summary.archive_file_count,
        "analysis_file_count": manifest_summary.analysis_file_count,
        "detected_languages": list(detected_languages),
        "language_file_counts": manifest_summary.language_file_counts,
        "rulepack_version": rulepack_manifest.version,
        "ruleset_digest": rulepack_manifest.digest,
        "registered_rule_count": len(rulepack_manifest.rule_ids),
        "supported_rule_count": rule_count_snapshot,
    }
    if any(snapshot.get(key) != value for key, value in expected.items()):
        raise ScanSnapshotConflictError("scan metadata does not match the completed file manifest")
    if (
        snapshot.get("engine_name") is None
        or snapshot.get("engine_version") is None
        or snapshot.get("rulepack_name") is None
        or type(snapshot.get("total_units")) is not int
        or type(snapshot.get("completed_units")) is not int
        or snapshot["completed_units"] > snapshot["total_units"]
        or snapshot.get("archive_data") is None
        or snapshot.get("manifest_version") is not None
        or snapshot.get("manifest_node_count") is not None
        or snapshot.get("issue_model_version") is not None
        or snapshot.get("manifest_summary_version") is not None
        or snapshot.get("issue_summary_version") is not None
        or snapshot.get("language_coverage_result_count") is not None
    ):
        raise ScanSnapshotConflictError("scan completion snapshot is incomplete or conflicting")


def _normalize_manifest_query_path(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        normalized = normalize_archive_path(path)
    except UnsafeArchiveError as exc:
        raise ScanFileParentNotFoundError(path) from exc
    if normalized != path:
        raise ScanFileParentNotFoundError(path)
    return normalized


def _validate_issue_filters(filters: IssueFilters) -> IssueFilters:
    result_status = filters.result_status.strip() if filters.result_status else None
    severity = filters.severity.strip() if filters.severity else None
    language = filters.language.strip() if filters.language else None
    weakness_id = filters.weakness_id.strip() if filters.weakness_id else None
    path = filters.path
    path_scope = filters.path_scope
    if result_status not in {None, ResultStatus.DETECTED.value, ResultStatus.REVIEW_REQUIRED.value}:
        raise InvalidIssueFilterError("status filter is invalid")
    if severity not in {None, *(item.value for item in IssueSeverity)}:
        raise InvalidIssueFilterError("severity filter is invalid")
    if language not in {None, "Java", "JavaScript", "Python"}:
        raise InvalidIssueFilterError("language filter is invalid")
    if weakness_id is not None and weakness_id not in CANONICAL_WEAKNESS_IDS:
        raise InvalidIssueFilterError("weaknessId filter is invalid")
    if (path is None) != (path_scope is None):
        raise InvalidIssueFilterError("path and pathScope must be provided together")
    normalized_path = None
    if path is not None:
        try:
            normalized_path = normalize_archive_path(path)
        except UnsafeArchiveError as exc:
            raise InvalidIssueFilterError("path filter is invalid") from exc
        if normalized_path != path:
            raise InvalidIssueFilterError("path filter must be normalized")
    return IssueFilters(
        result_status=result_status,
        severity=severity,
        language=language,
        weakness_id=weakness_id,
        path=normalized_path,
        path_scope=path_scope,
    )


def _issue_filter_sql(scan_id: str, filters: IssueFilters) -> tuple[str, list[object]]:
    clauses = ["issue.scan_id = %s"]
    parameters: list[object] = [scan_id]
    if filters.result_status is not None:
        clauses.append("issue.result_status = %s")
        parameters.append(filters.result_status)
    if filters.severity is not None:
        clauses.append("issue.severity = %s")
        parameters.append(filters.severity)
    if filters.language is not None:
        clauses.append("issue.language = %s")
        parameters.append(filters.language)
    if filters.weakness_id is not None:
        clauses.append("issue.weakness_id = %s")
        parameters.append(filters.weakness_id)
    if filters.path is not None:
        if filters.path_scope is IssuePathScope.FILE:
            clauses.append("issue.path = %s")
            parameters.append(filters.path)
        else:
            clauses.append("starts_with(issue.path, %s)")
            parameters.append(f"{filters.path}/")
    return " AND ".join(clauses), parameters


def _issue_list_item_from_row(row: dict[str, Any]) -> IssueListItem:
    issue = _validate_stored_issues([row])[0]
    return IssueListItem(
        issue_id=str(row["issue_id"]),
        fingerprint=issue.fingerprint,
        fingerprint_version=issue.fingerprint_version,
        result_status=issue.result_status,
        finding_kind=issue.finding_kind,
        detection_basis_version=issue.detection_basis_version,
        confidence=issue.confidence,
        detection_rationale=issue.detection_rationale,
        severity=issue.severity,
        weakness_id=issue.weakness_id,
        weakness_number=issue.weakness_number,
        weakness_name=issue.weakness_name,
        implementation_status=issue.implementation_status,
        rule_id=issue.rule_id,
        language=issue.language,
        path=issue.path,
        start_line=issue.start_line,
        start_column=issue.start_column,
        end_line=issue.end_line,
        end_column=issue.end_column,
        message=issue.message,
    )


def _issue_stats_from_row(row: dict[str, Any]) -> IssueStats:
    stats = IssueStats(
        total_issue_count=int(row["total_issue_count"]),
        detected_issue_count=int(row["detected_issue_count"]),
        review_signal_count=int(row["review_signal_count"]),
        severity_counts=IssueSeverityCounts(
            ERROR=int(row["severity_error"]),
            WARNING=int(row["severity_warning"]),
            INFO=int(row["severity_info"]),
        ),
    )
    _validate_issue_stats(stats)
    return stats


def _issue_stats_from_issues(issues: Sequence[NormalizedIssue]) -> IssueStats:
    detected = [issue for issue in issues if issue.result_status is ResultStatus.DETECTED]
    stats = IssueStats(
        total_issue_count=len(issues),
        detected_issue_count=len(detected),
        review_signal_count=sum(
            issue.result_status is ResultStatus.REVIEW_REQUIRED for issue in issues
        ),
        severity_counts=IssueSeverityCounts(
            ERROR=sum(issue.severity is IssueSeverity.ERROR for issue in detected),
            WARNING=sum(issue.severity is IssueSeverity.WARNING for issue in detected),
            INFO=sum(issue.severity is IssueSeverity.INFO for issue in detected),
        ),
    )
    _validate_issue_stats(stats)
    return stats


def _validate_issue_stats(stats: IssueStats) -> None:
    if stats.total_issue_count != (stats.detected_issue_count + stats.review_signal_count):
        raise CorruptScanIssueModelError("issue status statistics are inconsistent")
    severity_total = (
        stats.severity_counts.error + stats.severity_counts.warning + stats.severity_counts.info
    )
    if severity_total != stats.detected_issue_count:
        raise CorruptScanIssueModelError("severity statistics must include DETECTED issues only")


def _engine_snapshot_from_row(row: dict[str, Any]) -> EngineSnapshot:
    snapshot_fields = (
        "engine_name",
        "engine_version",
        "rulepack_name",
        "rulepack_version",
        "ruleset_digest",
        "registered_rule_count",
        "supported_rule_count",
    )
    if any(row.get(field) is None for field in snapshot_fields):
        raise ValueError("issue engine snapshot is incomplete")
    return EngineSnapshot(
        engine_name=row["engine_name"],
        engine_version=row["engine_version"],
        rulepack_name=row["rulepack_name"],
        rulepack_version=row["rulepack_version"],
        ruleset_digest=row["ruleset_digest"],
        registered_rule_count=row["registered_rule_count"],
        executed_rule_count=row["supported_rule_count"],
    )


def _issue_detail_from_row(
    row: dict[str, Any],
    *,
    engine_snapshot: EngineSnapshot | None = None,
    guidance_version: int,
    cwe_index_url: str,
    cwe_definition_url_template: str,
) -> IssueDetail:
    issue = _validate_stored_issues([row])[0]
    guidance = _validate_issue_guidance_row(
        row,
        issue,
        guidance_version=guidance_version,
        cwe_index_url=cwe_index_url,
        cwe_definition_url_template=cwe_definition_url_template,
    )
    if engine_snapshot is None:
        try:
            engine_snapshot = _engine_snapshot_from_row(row)
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptScanIssueModelError("issue engine snapshot is incomplete") from exc
    return IssueDetail(
        scan_id=str(row["scan_id"]),
        issue_id=str(row["issue_id"]),
        fingerprint=issue.fingerprint,
        fingerprint_version=issue.fingerprint_version,
        result_status=issue.result_status,
        finding_kind=issue.finding_kind,
        detection_basis_version=issue.detection_basis_version,
        confidence=issue.confidence,
        detection_rationale=issue.detection_rationale,
        weakness=IssueWeaknessSnapshot(
            weakness_id=issue.weakness_id,
            number=issue.weakness_number,
            category=issue.weakness_category,
            category_number=issue.weakness_category_number,
            name=issue.weakness_name,
            description=issue.weakness_description,
            sast_classification=issue.sast_classification,
            implementation_status=issue.implementation_status,
        ),
        rule=IssueRuleSnapshot(
            rule_id=issue.rule_id,
            language=issue.language,
            severity=issue.severity,
            message=issue.message,
            description=issue.rule_description,
            cwe_id=issue.cwe_id,
        ),
        location=IssueLocation(
            path=issue.path,
            start_line=issue.start_line,
            start_column=issue.start_column,
            end_line=issue.end_line,
            end_column=issue.end_column,
        ),
        engine_snapshot=engine_snapshot,
        evidence=IssueEvidence(),
        automation_limitation=guidance.automation_limitation,
        manual_verification_checks=list(guidance.manual_verification_checks),
        remediation=guidance.remediation,
        safe_implementation_example=guidance.safe_implementation_example,
        references=list(guidance.references),
    )


def _coverage_summary(
    items: Sequence[CoverageItem], *, issue_stats: IssueStats | None
) -> CoverageSummary:
    total_findings = sum(item.finding_count for item in items)
    if issue_stats is not None and total_findings != issue_stats.total_issue_count:
        raise CorruptScanIssueModelError("coverage and issue finding totals disagree")
    return CoverageSummary(
        total_criterion_count=len(items),
        detected_criterion_count=sum(item.result_status is ResultStatus.DETECTED for item in items),
        review_required_criterion_count=sum(
            item.result_status is ResultStatus.REVIEW_REQUIRED for item in items
        ),
        not_detected_criterion_count=sum(
            item.result_status is ResultStatus.NOT_DETECTED for item in items
        ),
        not_supported_criterion_count=sum(
            item.result_status is ResultStatus.NOT_SUPPORTED for item in items
        ),
        total_finding_count=total_findings,
        issue_stats=issue_stats,
    )


def _coverage_summary_v2(
    items: Sequence[CoverageCriterionV2], *, issue_stats: IssueStats
) -> CoverageSummaryV2:
    total_findings = sum(item.finding_count for item in items)
    if total_findings != issue_stats.total_issue_count or issue_stats.review_signal_count != 0:
        raise CorruptScanIssueModelError("v2 coverage and DETECTED issue totals disagree")

    def criterion_state(item: CoverageCriterionV2) -> ResultStatus:
        states = {language.result_status for language in item.languages}
        if ResultStatus.DETECTED in states:
            return ResultStatus.DETECTED
        if ResultStatus.CHECK_FAILED in states:
            return ResultStatus.CHECK_FAILED
        if ResultStatus.NOT_DETECTED in states:
            return ResultStatus.NOT_DETECTED
        return ResultStatus.NOT_SUPPORTED

    states = [criterion_state(item) for item in items]
    return CoverageSummaryV2(
        total_criterion_count=len(items),
        detected_criterion_count=states.count(ResultStatus.DETECTED),
        not_detected_criterion_count=states.count(ResultStatus.NOT_DETECTED),
        not_supported_criterion_count=states.count(ResultStatus.NOT_SUPPORTED),
        check_failed_criterion_count=states.count(ResultStatus.CHECK_FAILED),
        total_language_result_count=sum(len(item.languages) for item in items),
        total_finding_count=total_findings,
        issue_stats=_v2_issue_stats(issue_stats),
    )


def _v2_issue_stats(stats: IssueStats) -> IssueStatsV2:
    if stats.review_signal_count != 0:
        raise CorruptScanIssueModelError("v2 issue statistics cannot contain review signals")
    return IssueStatsV2(
        total_issue_count=stats.total_issue_count,
        detected_issue_count=stats.detected_issue_count,
        severity_counts=stats.severity_counts,
    )


def _is_valid_issue_position_key(value: tuple[object, ...]) -> bool:
    weakness_number, path, start_line, start_column, issue_id = value
    if (
        type(weakness_number) is not int
        or not 1 <= weakness_number <= 49
        or not isinstance(path, str)
        or type(start_line) is not int
        or start_line < 1
        or type(start_column) is not int
        or start_column < 1
        or not isinstance(issue_id, str)
    ):
        return False
    try:
        return normalize_archive_path(path) == path and str(UUID(issue_id)) == issue_id
    except (UnsafeArchiveError, ValueError):
        return False


def _scan_file_node_from_row(row: dict[str, Any]) -> ScanFileNode:
    path = row.get("path")
    if not isinstance(path, str):
        raise ValueError("manifest path must be a string")
    entry_type = row.get("node_type")
    payload = {
        "path": path,
        "parent_path": row.get("parent_path"),
        "name": PurePosixPath(path).name,
        "depth": row.get("depth"),
        "entry_type": entry_type,
        "size_bytes": None if entry_type == "DIRECTORY" else row.get("size"),
        "language": row.get("language"),
        "analysis_state": row.get("state"),
        "finding_count": row.get("finding_count"),
        "has_children": row.get("has_children"),
    }
    node = ScanFileNode.model_validate(payload)
    validate_scan_file_node_structure(node)
    return node


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if not value or any(character not in alphabet for character in value):
        raise binascii.Error("invalid base64url")
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def _progress_from_row(row: dict[str, Any]) -> ScanProgress:
    snapshot = None
    if row.get("engine_name") is not None:
        snapshot = {
            "engine_name": row["engine_name"],
            "engine_version": row["engine_version"],
            "rulepack_name": row["rulepack_name"],
            "rulepack_version": row["rulepack_version"],
            "ruleset_digest": row["ruleset_digest"],
            "registered_rule_count": row["registered_rule_count"],
            "executed_rule_count": row.get("supported_rule_count"),
        }
    return ScanProgress.model_validate(
        {
            "scan_id": str(row["id"]),
            "project_id": row["project_id"],
            "archive_name": row["archive_name"],
            "status": row["status"],
            "phase": row["phase"],
            "progress_percent": row["progress_percent"],
            "completed_units": row["completed_units"],
            "total_units": row["total_units"],
            "message": row["message"],
            "error_code": row["error_code"],
            "archive_file_count": row.get("archive_file_count"),
            "analysis_file_count": row.get("analysis_file_count"),
            "detected_languages": row.get("detected_languages", []),
            "language_file_counts": row.get("language_file_counts", {}),
            "engine_snapshot": snapshot,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


def _user_summary_from_row(row: dict[str, Any]) -> UserSummary:
    return UserSummary(
        id=str(row["id"]),
        email=str(row["email"]),
        role=UserRole(str(row["role"])),
        is_active=bool(row["is_active"]),
        invitation_pending=bool(row.get("invitation_pending", False)),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _user_credential_from_row(row: dict[str, Any]) -> UserCredential:
    return UserCredential(
        id=str(row["id"]),
        email=str(row["email"]),
        password_hash=str(row["password_hash"]) if row["password_hash"] is not None else None,
        role=UserRole(str(row["role"])),
        is_active=bool(row["is_active"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _authenticated_user_from_rows(
    user_row: dict[str, Any], expires_at: datetime
) -> AuthenticatedUser:
    user = _user_summary_from_row(user_row)
    return AuthenticatedUser(**user.model_dump(), session_expires_at=expires_at)


def _project_from_row(row: dict[str, Any]) -> Project:
    latest_scan = row.get("latest_scan")
    return Project.model_validate(
        {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "assigned_to_viewer": row["assigned_to_viewer"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "latest_scan": _progress_from_row(latest_scan) if latest_scan else None,
        }
    )
