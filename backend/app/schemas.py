from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.catalog import ImplementationStatus
from app.rule_registry import FindingKind

CANONICAL_WEAKNESS_ID_SEQUENCE = tuple(f"KISA-2021-{number:02d}" for number in range(1, 50))
CANONICAL_WEAKNESS_NUMBER_SEQUENCE = tuple(range(1, 50))


def to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanPhase(StrEnum):
    PENDING = "PENDING"
    ZIP_VALIDATION = "ZIP_VALIDATION"
    LANGUAGE_DETECTION = "LANGUAGE_DETECTION"
    ANALYZING = "ANALYZING"
    NORMALIZING = "NORMALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class UserRole(StrEnum):
    ADMIN = "ADMIN"
    USER = "USER"


class LoginRequest(ApiModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class UserInviteRequest(ApiModel):
    email: str = Field(min_length=3, max_length=320)


class InvitationAcceptRequest(ApiModel):
    token: str = Field(min_length=32, max_length=512)
    password: str = Field(min_length=12, max_length=1024)


class UserUpdate(ApiModel):
    is_active: bool


class UserSummary(ApiModel):
    id: str
    email: str
    role: UserRole
    is_active: bool
    invitation_pending: bool = False
    created_at: datetime
    updated_at: datetime


class AuthenticatedUser(UserSummary):
    session_expires_at: datetime


class UserList(ApiModel):
    items: list[UserSummary]


class ProjectMemberList(ApiModel):
    user_ids: list[str]


class ProjectMembersUpdate(ApiModel):
    user_ids: list[str] = Field(max_length=1000)


class SupportStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class ResultStatus(StrEnum):
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    CHECK_FAILED = "CHECK_FAILED"


class ScanFileType(StrEnum):
    DIRECTORY = "DIRECTORY"
    FILE = "FILE"


class ScanFileState(StrEnum):
    DIRECTORY = "DIRECTORY"
    TARGET = "TARGET"
    EXCLUDED_DIRECTORY = "EXCLUDED_DIRECTORY"
    UNSUPPORTED_EXTENSION = "UNSUPPORTED_EXTENSION"


class ManifestUnavailableReason(StrEnum):
    LEGACY_SCAN = "LEGACY_SCAN"


class IssueUnavailableReason(StrEnum):
    LEGACY_SCAN = "LEGACY_SCAN"


class IssueSeverity(StrEnum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class IssueConfidence(StrEnum):
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IssuePathScope(StrEnum):
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"


class EngineSnapshot(ApiModel):
    engine_name: str
    engine_version: str
    rulepack_name: str
    rulepack_version: str
    ruleset_digest: str
    registered_rule_count: int = Field(ge=0)
    executed_rule_count: int | None = Field(default=None, ge=0)


class ScanProgress(ApiModel):
    scan_id: str
    project_id: str
    archive_name: str
    status: ScanStatus
    phase: ScanPhase
    progress_percent: int | None = Field(default=None, ge=0, le=100)
    completed_units: int = Field(ge=0)
    total_units: int | None = Field(default=None, ge=1)
    message: str
    error_code: str | None = None
    archive_file_count: int | None = Field(default=None, ge=0)
    analysis_file_count: int | None = Field(default=None, ge=0)
    detected_languages: list[str] = Field(default_factory=list)
    language_file_counts: dict[str, int] = Field(default_factory=dict)
    engine_snapshot: EngineSnapshot | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_progress_invariants(self) -> Self:
        if self.total_units is not None and self.completed_units > self.total_units:
            raise ValueError("completed_units cannot exceed total_units")
        if self.status is ScanStatus.COMPLETED:
            if self.progress_percent != 100 or self.completed_units != self.total_units:
                raise ValueError("completed scans must finish all units at 100 percent")
        elif self.progress_percent == 100:
            raise ValueError("only completed scans may report 100 percent")
        if any(count < 0 for count in self.language_file_counts.values()):
            raise ValueError("language file counts cannot be negative")
        if (
            self.archive_file_count is not None
            and self.analysis_file_count is not None
            and self.analysis_file_count > self.archive_file_count
        ):
            raise ValueError("analysis_file_count cannot exceed archive_file_count")
        if self.analysis_file_count is not None:
            if set(self.language_file_counts) != set(self.detected_languages):
                raise ValueError("language file counts must match detected languages")
            if sum(self.language_file_counts.values()) != self.analysis_file_count:
                raise ValueError("language file counts must sum to analysis_file_count")
        return self


class ProjectCreate(ApiModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    assigned_to_viewer: bool = False
    member_user_ids: list[str] = Field(default_factory=list, max_length=1000)


class ProjectUpdate(ApiModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    assigned_to_viewer: bool = False
    member_user_ids: list[str] = Field(default_factory=list, max_length=1000)


class Project(ApiModel):
    id: str
    name: str
    description: str
    assigned_to_viewer: bool
    created_at: datetime
    updated_at: datetime
    latest_scan: ScanProgress | None = None


class ProjectList(ApiModel):
    items: list[Project]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class ScanList(ApiModel):
    items: list[ScanProgress]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class ScanFileNode(ApiModel):
    path: str = Field(min_length=1, max_length=4096)
    parent_path: str | None = Field(default=None, max_length=4096)
    name: str = Field(min_length=1, max_length=255)
    depth: int = Field(ge=1, le=64)
    entry_type: ScanFileType
    size_bytes: int | None = Field(default=None, ge=0)
    language: str | None = None
    analysis_state: ScanFileState
    finding_count: int = Field(ge=0)
    has_children: bool

    @model_validator(mode="after")
    def validate_node_shape(self) -> Self:
        if self.name != self.path.rsplit("/", 1)[-1]:
            raise ValueError("manifest node name must match the path basename")
        if self.entry_type is ScanFileType.DIRECTORY:
            if (
                self.analysis_state is not ScanFileState.DIRECTORY
                or self.size_bytes is not None
                or self.language is not None
            ):
                raise ValueError("directory nodes must use DIRECTORY state without file metadata")
        else:
            if self.analysis_state is ScanFileState.DIRECTORY or self.size_bytes is None:
                raise ValueError("file nodes cannot use DIRECTORY state")
            if self.has_children:
                raise ValueError("file nodes cannot have children")
            if (self.analysis_state is ScanFileState.TARGET) != (self.language is not None):
                raise ValueError("only TARGET files may carry a detected language")
        return self


class ScanFileList(ApiModel):
    scan_id: str
    manifest_available: bool
    manifest_version: int | None = Field(default=None, ge=1)
    unavailable_reason: ManifestUnavailableReason | None = None
    parent_path: str | None = None
    items: list[ScanFileNode] = Field(default_factory=list)
    next_cursor: str | None = None

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.manifest_available:
            if self.manifest_version != 1 or self.unavailable_reason is not None:
                raise ValueError("available manifests cannot have an unavailable reason")
        elif (
            self.manifest_version is not None
            or self.unavailable_reason is not ManifestUnavailableReason.LEGACY_SCAN
            or self.items
            or self.next_cursor is not None
        ):
            raise ValueError("legacy manifests must be empty and explicitly unavailable")
        return self


class Finding(ApiModel):
    rule_id: str
    kind: FindingKind | None = None
    language: str
    path: str
    start_line: int = Field(ge=1)
    message: str
    severity: str


class CoverageResult(ApiModel):
    """A KISA criterion result without duplicated finding payloads."""

    weakness_id: str
    number: int = Field(ge=1, le=49)
    category: str
    category_number: int = Field(ge=1)
    name: str
    description: str | None = None
    sast_classification: str
    implementation_status: ImplementationStatus | None = None
    support_status: SupportStatus
    result_status: ResultStatus
    reason: str


class CoverageCriterionSnapshot(ApiModel):
    """Immutable criterion metadata shared by every v2 language result."""

    weakness_id: str
    number: int = Field(ge=1, le=49)
    category: str
    category_number: int = Field(ge=1)
    name: str
    description: str | None = None
    sast_classification: str
    implementation_status: ImplementationStatus | None = None


class NormalizedIssue(BaseModel):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint_version: Literal[1] = 1
    result_status: Literal[ResultStatus.DETECTED, ResultStatus.REVIEW_REQUIRED]
    finding_kind: FindingKind
    detection_basis_version: Literal[1] = 1
    confidence: IssueConfidence
    detection_rationale: str = Field(min_length=1, max_length=4000)
    severity: IssueSeverity
    weakness_id: str
    weakness_number: int = Field(ge=1, le=49)
    weakness_name: str
    weakness_category: str
    weakness_category_number: int = Field(ge=1)
    weakness_description: str
    sast_classification: str
    implementation_status: ImplementationStatus
    rule_id: str
    language: str
    path: str = Field(min_length=1, max_length=4096)
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)
    message: str = Field(min_length=1, max_length=4000)
    rule_description: str | None = None
    cwe_id: str | None = None

    @model_validator(mode="after")
    def validate_issue_shape(self) -> Self:
        expected_status = (
            ResultStatus.DETECTED
            if self.finding_kind is FindingKind.DETECTED
            else ResultStatus.REVIEW_REQUIRED
        )
        if self.result_status is not expected_status:
            raise ValueError("finding kind and result status must agree")
        expected_confidence = (
            IssueConfidence.MEDIUM
            if self.finding_kind is FindingKind.DETECTED
            else IssueConfidence.LOW
        )
        if self.confidence is not expected_confidence:
            raise ValueError("finding kind and confidence must agree")
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("issue end position cannot precede its start position")
        return self


class IssueListItem(ApiModel):
    issue_id: str
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint_version: Literal[1]
    result_status: Literal[ResultStatus.DETECTED, ResultStatus.REVIEW_REQUIRED]
    finding_kind: FindingKind
    detection_basis_version: Literal[1]
    confidence: IssueConfidence
    detection_rationale: str = Field(min_length=1, max_length=4000)
    severity: IssueSeverity
    weakness_id: str
    weakness_number: int = Field(ge=1, le=49)
    weakness_name: str
    implementation_status: ImplementationStatus
    rule_id: str
    language: str
    path: str
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)
    message: str


class IssueSeverityCounts(ApiModel):
    error: int = Field(default=0, ge=0, alias="ERROR")
    warning: int = Field(default=0, ge=0, alias="WARNING")
    info: int = Field(default=0, ge=0, alias="INFO")


class IssueStats(ApiModel):
    total_issue_count: int = Field(ge=0)
    detected_issue_count: int = Field(ge=0)
    review_signal_count: int = Field(ge=0)
    severity_counts: IssueSeverityCounts


class IssueStatsV2(ApiModel):
    total_issue_count: int = Field(ge=0)
    detected_issue_count: int = Field(ge=0)
    severity_counts: IssueSeverityCounts


class IssueList(ApiModel):
    scan_id: str
    issue_model_available: bool
    unavailable_reason: IssueUnavailableReason | None = None
    items: list[IssueListItem] = Field(default_factory=list)
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    next_cursor: str | None = None
    stats: IssueStats | IssueStatsV2 | None = None

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.issue_model_available:
            if self.unavailable_reason is not None or self.stats is None:
                raise ValueError("available issue lists require stats")
        elif (
            self.unavailable_reason is not IssueUnavailableReason.LEGACY_SCAN
            or self.items
            or self.total != 0
            or self.next_cursor is not None
            or self.stats is not None
        ):
            raise ValueError("legacy issue lists must be explicitly empty")
        return self


class IssueWeaknessSnapshot(ApiModel):
    weakness_id: str
    number: int = Field(ge=1, le=49)
    category: str
    category_number: int = Field(ge=1)
    name: str
    description: str
    sast_classification: str
    implementation_status: ImplementationStatus


class IssueRuleSnapshot(ApiModel):
    rule_id: str
    language: str
    severity: IssueSeverity
    message: str
    description: str | None = None
    cwe_id: str | None = None


class IssueLocation(ApiModel):
    path: str
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)


class IssueEvidence(ApiModel):
    available: Literal[False] = False
    reason: Literal["SOURCE_NOT_RETAINED"] = "SOURCE_NOT_RETAINED"


class IssueDetail(ApiModel):
    scan_id: str
    issue_id: str
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint_version: Literal[1]
    result_status: Literal[ResultStatus.DETECTED, ResultStatus.REVIEW_REQUIRED]
    finding_kind: FindingKind
    detection_basis_version: Literal[1]
    confidence: IssueConfidence
    detection_rationale: str = Field(min_length=1, max_length=4000)
    weakness: IssueWeaknessSnapshot
    rule: IssueRuleSnapshot
    location: IssueLocation
    engine_snapshot: EngineSnapshot
    evidence: IssueEvidence = Field(default_factory=IssueEvidence)
    automation_limitation: str = Field(min_length=1, max_length=4000)
    manual_verification_checks: list[str] = Field(min_length=1, max_length=5)
    remediation: str = Field(min_length=1, max_length=4000)
    safe_implementation_example: str = Field(min_length=1, max_length=4000)
    references: list[str] = Field(min_length=1, max_length=3)


class CoverageItem(CoverageResult):
    finding_count: int = Field(ge=0)


class LanguageCoverageResult(ApiModel):
    language: str
    support_status: Literal[SupportStatus.SUPPORTED, SupportStatus.NOT_SUPPORTED]
    result_status: Literal[
        ResultStatus.DETECTED,
        ResultStatus.NOT_DETECTED,
        ResultStatus.NOT_SUPPORTED,
        ResultStatus.CHECK_FAILED,
    ]
    executed_rule_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=4000)

    @model_validator(mode="after")
    def validate_language_result(self) -> Self:
        if self.language not in {"Java", "JavaScript", "Python"}:
            raise ValueError("language coverage must use a supported detected language")
        if self.support_status is SupportStatus.NOT_SUPPORTED:
            if (
                self.result_status is not ResultStatus.NOT_SUPPORTED
                or self.executed_rule_count != 0
                or self.finding_count != 0
            ):
                raise ValueError(
                    "unsupported language coverage cannot execute rules or find issues"
                )
            return self
        if self.executed_rule_count < 1:
            raise ValueError("supported language coverage requires an executed verified rule")
        if self.result_status is ResultStatus.DETECTED and self.finding_count < 1:
            raise ValueError("DETECTED language coverage requires at least one issue")
        if self.result_status in {
            ResultStatus.NOT_DETECTED,
            ResultStatus.CHECK_FAILED,
        } and self.finding_count != 0:
            raise ValueError("non-detected language coverage cannot contain issues")
        if self.result_status is ResultStatus.NOT_SUPPORTED:
            raise ValueError("supported language coverage cannot be NOT_SUPPORTED")
        return self


class CoverageCriterionV2(ApiModel):
    weakness_id: str
    number: int = Field(ge=1, le=49)
    category: str
    category_number: int = Field(ge=1)
    name: str
    description: str | None = None
    sast_classification: str
    implementation_status: ImplementationStatus | None = None
    reason: str = Field(min_length=1, max_length=4000)
    finding_count: int = Field(ge=0)
    languages: list[LanguageCoverageResult]

    @model_validator(mode="after")
    def validate_language_rows(self) -> Self:
        if len({item.language for item in self.languages}) != len(self.languages):
            raise ValueError("criterion language coverage cannot contain duplicates")
        if self.finding_count != sum(item.finding_count for item in self.languages):
            raise ValueError("criterion finding count must equal its language rows")
        return self


class CoverageSummary(ApiModel):
    total_criterion_count: int = Field(ge=0)
    detected_criterion_count: int = Field(ge=0)
    review_required_criterion_count: int = Field(ge=0)
    not_detected_criterion_count: int = Field(ge=0)
    not_supported_criterion_count: int = Field(ge=0)
    check_failed_criterion_count: int = Field(default=0, ge=0)
    total_language_result_count: int = Field(default=0, ge=0)
    total_finding_count: int = Field(ge=0)
    issue_stats: IssueStats | IssueStatsV2 | None = None


class CoverageSummaryV2(ApiModel):
    total_criterion_count: Literal[49] = 49
    detected_criterion_count: int = Field(ge=0)
    not_detected_criterion_count: int = Field(ge=0)
    not_supported_criterion_count: int = Field(ge=0)
    check_failed_criterion_count: int = Field(default=0, ge=0)
    total_language_result_count: int = Field(ge=0)
    total_finding_count: int = Field(ge=0)
    issue_stats: IssueStatsV2


class ScanCoverage(ApiModel):
    scan_id: str
    coverage_model_version: Literal[1, 2] | None
    total_weakness_count: Literal[49] = 49
    summary: CoverageSummary | CoverageSummaryV2
    items: list[CoverageItem | CoverageCriterionV2]
    legacy_notice: str | None = None

    @model_validator(mode="after")
    def validate_complete_coverage(self) -> Self:
        actual_ids = tuple(item.weakness_id for item in self.items)
        actual_numbers = tuple(item.number for item in self.items)
        if (
            actual_ids != CANONICAL_WEAKNESS_ID_SEQUENCE
            or actual_numbers != CANONICAL_WEAKNESS_NUMBER_SEQUENCE
        ):
            raise ValueError("coverage must contain all 49 canonical criteria in order")
        if self.summary.total_criterion_count != 49:
            raise ValueError("coverage summary must contain 49 criteria")
        if self.coverage_model_version == 2:
            if not isinstance(self.summary, CoverageSummaryV2):
                raise ValueError("coverage model v2 requires its versioned summary")
            v2_items = [item for item in self.items if isinstance(item, CoverageCriterionV2)]
            if len(v2_items) != len(self.items):
                raise ValueError("coverage model v2 requires criterion-language rows")
            expected_languages = (
                tuple(language.language for language in v2_items[0].languages)
                if v2_items
                else ()
            )
            if any(
                tuple(language.language for language in item.languages) != expected_languages
                for item in v2_items
            ):
                raise ValueError("all v2 criteria must contain the same detected languages")
            if self.summary.total_language_result_count != 49 * len(expected_languages):
                raise ValueError("v2 language coverage must contain 49 rows per language")
            if self.legacy_notice is not None:
                raise ValueError("v2 coverage cannot carry a legacy notice")
        elif self.legacy_notice is None:
            self.legacy_notice = "이전 결과 모델로 생성됨 · 현재 기준으로 다시 분석 필요"
        return self


class WeaknessCatalogItem(ApiModel):
    weakness_id: str
    number: int
    category: str
    category_number: int
    name: str
    description: str
    sast_classification: str
    implementation_status: ImplementationStatus


class WeaknessResult(ApiModel):
    weakness_id: str
    number: int
    category: str
    category_number: int
    name: str
    description: str | None = None
    sast_classification: str
    implementation_status: ImplementationStatus | None = None
    support_status: SupportStatus
    result_status: ResultStatus
    reason: str
    finding_count: int = Field(ge=0)
    findings: list[Finding]

    @model_validator(mode="after")
    def validate_result_invariants(self) -> Self:
        if self.finding_count != len(self.findings):
            raise ValueError("finding_count must equal the number of findings")
        has_findings = bool(self.findings)
        if self.implementation_status is None:
            return self
        if self.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED:
            if (
                self.support_status is not SupportStatus.MANUAL_REVIEW_REQUIRED
                or self.result_status is not ResultStatus.REVIEW_REQUIRED
            ):
                raise ValueError(
                    "manual review criteria must remain MANUAL_REVIEW_REQUIRED and REVIEW_REQUIRED"
                )
            if any(finding.kind is not FindingKind.REVIEW_SIGNAL for finding in self.findings):
                raise ValueError("manual review criteria may contain only REVIEW_SIGNAL findings")
        elif self.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED:
            allowed = {
                (SupportStatus.PARTIALLY_SUPPORTED, ResultStatus.DETECTED),
                (SupportStatus.PARTIALLY_SUPPORTED, ResultStatus.REVIEW_REQUIRED),
                (SupportStatus.NOT_SUPPORTED, ResultStatus.NOT_SUPPORTED),
            }
            if (self.support_status, self.result_status) not in allowed:
                raise ValueError("invalid partially implemented result state")
            if has_findings and self.result_status is not ResultStatus.DETECTED:
                raise ValueError("partial-rule findings must produce a DETECTED result")
            if any(finding.kind is not FindingKind.DETECTED for finding in self.findings):
                raise ValueError("automated criteria may contain only DETECTED findings")
        elif self.implementation_status is ImplementationStatus.IMPLEMENTED:
            allowed = {
                (SupportStatus.SUPPORTED, ResultStatus.DETECTED),
                (SupportStatus.SUPPORTED, ResultStatus.NOT_DETECTED),
                (SupportStatus.NOT_SUPPORTED, ResultStatus.NOT_SUPPORTED),
            }
            if (self.support_status, self.result_status) not in allowed:
                raise ValueError("invalid implemented result state")
            if any(finding.kind is not FindingKind.DETECTED for finding in self.findings):
                raise ValueError("automated criteria may contain only DETECTED findings")
        elif (
            self.support_status is not SupportStatus.NOT_SUPPORTED
            or self.result_status is not ResultStatus.NOT_SUPPORTED
            or has_findings
        ):
            raise ValueError("unimplemented criteria must remain NOT_SUPPORTED without findings")

        if self.result_status is ResultStatus.DETECTED and not has_findings:
            raise ValueError("DETECTED results must contain at least one finding")
        if self.result_status in {ResultStatus.NOT_DETECTED, ResultStatus.NOT_SUPPORTED} and (
            has_findings
        ):
            raise ValueError("NOT_DETECTED and NOT_SUPPORTED results cannot contain findings")
        return self


class ScanResults(ApiModel):
    scan_id: str
    status: ScanStatus
    detected_languages: list[str]
    supported_rule_count: int | None = Field(default=None, ge=0)
    rulepack_version: str | None = None
    total_weakness_count: int
    results: list[WeaknessResult]

    @model_validator(mode="after")
    def validate_complete_coverage(self) -> Self:
        actual_ids = tuple(result.weakness_id for result in self.results)
        actual_numbers = tuple(result.number for result in self.results)
        if (
            self.total_weakness_count != 49
            or actual_ids != CANONICAL_WEAKNESS_ID_SEQUENCE
            or actual_numbers != CANONICAL_WEAKNESS_NUMBER_SEQUENCE
        ):
            raise ValueError("completed results must contain all 49 canonical weaknesses")
        return self


class ClaimedScan(BaseModel):
    scan_id: str
    project_id: str
    archive_data: bytes
    worker_id: str
    attempts: int


JsonObject = dict[str, Any]
