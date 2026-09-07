from collections.abc import Iterator
from datetime import UTC, datetime
from typing import cast

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.auth import hash_password
from app.catalog import KISA_CATALOG
from app.database import (
    CorruptScanIssueModelError,
    CorruptScanManifestError,
    InvalidIssueFilterError,
    InvalidIssuesCursorError,
    InvalidScanFilesCursorError,
    LegacyIssueModelUnavailableError,
    ProjectHasActiveScansError,
    ProjectNotFoundError,
    ScanFileParentNotFoundError,
    ScanFilesNotReadyError,
    ScanIssuesNotReadyError,
    ScanRepository,
    UserCredential,
)
from app.schemas import (
    AuthenticatedUser,
    CoverageCriterionV2,
    CoverageSummaryV2,
    EngineSnapshot,
    IssueDetail,
    IssueEvidence,
    IssueList,
    IssueListItem,
    IssueLocation,
    IssueRuleSnapshot,
    IssueSeverityCounts,
    IssueStats,
    IssueStatsV2,
    IssueWeaknessSnapshot,
    LanguageCoverageResult,
    Project,
    ProjectCreate,
    ProjectList,
    ProjectUpdate,
    ScanCoverage,
    ScanFileList,
    ScanFileNode,
    ScanList,
    ScanProgress,
    ScanResults,
    UserRole,
    UserSummary,
)


class FakeRepository:
    def __init__(self) -> None:
        self.created: tuple[str, str, str, bytes] | None = None
        self.scan: ScanProgress | None = None
        self.projects: dict[str, Project] = {
            "payments-api": self._project("payments-api", "Payments API")
        }
        self.active_project_delete = False
        self.last_project_filters: tuple[str | None, str | None] | None = None
        self.last_member_user_id: str | None = None
        self.project_member_ids: dict[str, list[str]] = {"payments-api": []}
        self.files_error: Exception | None = None
        self.issues_error: Exception | None = None
        self.issue_detail_error: Exception | None = None
        self.coverage_error: Exception | None = None
        self.last_issue_filters: object | None = None
        self.file_list: ScanFileList | None = ScanFileList(
            scan_id="52f03ca1-2434-40e3-9c3e-c0c598571cb8",
            manifest_available=False,
            manifest_version=None,
            unavailable_reason="LEGACY_SCAN",
            parent_path=None,
        )
        self.issue_list: IssueList | None = IssueList(
            scan_id="52f03ca1-2434-40e3-9c3e-c0c598571cb8",
            issue_model_available=False,
            unavailable_reason="LEGACY_SCAN",
            total=0,
            limit=50,
        )
        self.issue_detail: IssueDetail | None = None
        self.coverage: ScanCoverage | None = None

    @staticmethod
    def _project(project_id: str, name: str) -> Project:
        now = datetime.now(UTC)
        return Project(
            id=project_id,
            name=name,
            description="",
            assigned_to_viewer=False,
            created_at=now,
            updated_at=now,
        )

    def create_project(self, project: ProjectCreate) -> Project:
        created = self._project("generated-project-id", project.name)
        created.description = project.description
        created.assigned_to_viewer = project.assigned_to_viewer
        self.projects[created.id] = created
        self.project_member_ids[created.id] = sorted(set(project.member_user_ids))
        return created

    def list_projects(
        self,
        *,
        query: str | None,
        language: str | None,
        limit: int,
        offset: int,
        member_user_id: str | None = None,
    ) -> ProjectList:
        self.last_project_filters = (query, language)
        self.last_member_user_id = member_user_id
        items = list(self.projects.values())
        if query:
            normalized_query = query.casefold()
            items = [
                project
                for project in items
                if normalized_query in f"{project.name} {project.description}".casefold()
            ]
        if language:
            items = [
                project
                for project in items
                if project.latest_scan and language in project.latest_scan.detected_languages
            ]
        return ProjectList(
            items=items[offset : offset + limit],
            total=len(items),
            limit=limit,
            offset=offset,
        )

    def get_project(self, project_id: str) -> Project | None:
        return self.projects.get(project_id)

    def update_project(self, project_id: str, project: ProjectUpdate) -> Project | None:
        current = self.projects.get(project_id)
        if current is None:
            return None
        updated = current.model_copy(
            update={
                "name": project.name,
                "description": project.description,
                "assigned_to_viewer": project.assigned_to_viewer,
                "updated_at": datetime.now(UTC),
            }
        )
        self.projects[project_id] = updated
        self.project_member_ids[project_id] = sorted(set(project.member_user_ids))
        return updated

    def delete_project(self, project_id: str) -> bool:
        if self.active_project_delete:
            raise ProjectHasActiveScansError(project_id)
        return self.projects.pop(project_id, None) is not None

    def list_project_scans(self, project_id: str, *, limit: int, offset: int) -> ScanList:
        if project_id not in self.projects:
            raise ProjectNotFoundError(project_id)
        scans = [self.scan] if self.scan and self.scan.project_id == project_id else []
        return ScanList(
            items=scans[offset : offset + limit],
            total=len(scans),
            limit=limit,
            offset=offset,
        )

    def create_scan(
        self, scan_id: str, project_id: str, archive_name: str, archive_data: bytes
    ) -> ScanProgress:
        if project_id not in self.projects:
            raise ProjectNotFoundError(project_id)
        self.created = (scan_id, project_id, archive_name, archive_data)
        now = datetime.now(UTC)
        self.scan = ScanProgress(
            scan_id=scan_id,
            project_id=project_id,
            archive_name=archive_name,
            status="PENDING",
            phase="PENDING",
            progress_percent=None,
            completed_units=0,
            total_units=None,
            message="분석 작업이 대기 중입니다.",
            created_at=now,
            updated_at=now,
        )
        return self.scan

    def get_scan(self, scan_id: str) -> ScanProgress | None:
        return self.scan if self.scan and self.scan.scan_id == scan_id else None

    def get_results(self, scan_id: str) -> ScanResults | None:
        return None

    def get_scan_files(
        self,
        scan_id: str,
        *,
        parent_path: str | None,
        limit: int,
        cursor: str | None,
    ) -> ScanFileList | None:
        if self.files_error is not None:
            raise self.files_error
        return self.file_list

    def get_scan_issues(
        self, scan_id: str, *, filters: object, limit: int, cursor: str | None
    ) -> IssueList | None:
        if self.issues_error is not None:
            raise self.issues_error
        self.last_issue_filters = (filters, limit, cursor)
        return self.issue_list

    def get_scan_issue(self, scan_id: str, issue_id: str) -> IssueDetail | None:
        if self.issue_detail_error is not None:
            raise self.issue_detail_error
        return self.issue_detail

    def get_scan_coverage(self, scan_id: str) -> ScanCoverage | None:
        if self.coverage_error is not None:
            raise self.coverage_error
        return self.coverage


@pytest.fixture
def fake_repository(monkeypatch: pytest.MonkeyPatch) -> FakeRepository:
    repository = FakeRepository()
    monkeypatch.setattr(main_module, "repository", cast(ScanRepository, repository))
    return repository


@pytest.fixture(autouse=True)
def authenticated_admin() -> Iterator[None]:
    now = datetime.now(UTC)
    admin = AuthenticatedUser(
        id="11111111-1111-1111-1111-111111111111",
        email="admin@toy-sast.local",
        role=UserRole.ADMIN,
        is_active=True,
        created_at=now,
        updated_at=now,
        session_expires_at=now,
    )
    main_module.app.dependency_overrides[main_module.get_current_user] = lambda: admin
    main_module.app.dependency_overrides[main_module.require_allowed_origin] = lambda: None
    yield
    main_module.app.dependency_overrides.clear()


def authenticated_user() -> AuthenticatedUser:
    now = datetime.now(UTC)
    return AuthenticatedUser(
        id="22222222-2222-2222-2222-222222222222",
        email="viewer@toy-sast.local",
        role=UserRole.USER,
        is_active=True,
        created_at=now,
        updated_at=now,
        session_expires_at=now,
    )


def test_login_sets_an_opaque_http_only_session_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main_module.app.dependency_overrides.pop(main_module.require_allowed_origin)
    now = datetime.now(UTC)
    credential = UserCredential(
        id="11111111-1111-1111-1111-111111111111",
        email="admin@example.com",
        password_hash=hash_password("a-long-test-password"),
        role=UserRole.ADMIN,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    monkeypatch.setattr(
        main_module.auth_database,
        "get_user_credentials_by_email",
        lambda email: credential if email == credential.email else None,
    )
    monkeypatch.setattr(
        main_module.auth_database,
        "create_session",
        lambda _token_hash, _user_id, *, expires_at: AuthenticatedUser(
            **credential.__dict__, session_expires_at=expires_at
        ),
    )

    response = TestClient(main_module.app).post(
        "/api/auth/login",
        headers={"Origin": main_module.settings.web_origin},
        json={"email": " ADMIN@example.com ", "password": "a-long-test-password"},
    )

    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "toy_sast_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie


def test_login_rejects_requests_from_an_untrusted_origin() -> None:
    main_module.app.dependency_overrides.pop(main_module.require_allowed_origin)

    response = TestClient(main_module.app).post(
        "/api/auth/login",
        headers={"Origin": "https://attacker.invalid"},
        json={"email": "admin@example.com", "password": "a-long-test-password"},
    )

    assert response.status_code == 403


def test_admin_invites_a_user_by_email(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC)
    invited = UserSummary(
        id="33333333-3333-3333-3333-333333333333",
        email="viewer@example.com",
        role=UserRole.USER,
        is_active=False,
        invitation_pending=True,
        created_at=now,
        updated_at=now,
    )
    saved: dict[str, object] = {}
    monkeypatch.setattr(
        main_module.auth_database,
        "save_user_invitation",
        lambda _user_id, **values: saved.update(values) or invited,
    )
    monkeypatch.setattr(
        main_module,
        "send_invitation_email",
        lambda **values: saved.update({"mail": values}),
    )

    response = TestClient(main_module.app).post(
        "/api/admin/users/invitations", json={"email": " Viewer@Example.com "}
    )

    assert response.status_code == 201
    assert response.json()["invitationPending"] is True
    assert saved["email"] == "viewer@example.com"
    assert "token=" in cast(dict[str, str], saved["mail"])["invitation_url"]


def test_invitation_acceptance_sets_password_once(monkeypatch: pytest.MonkeyPatch) -> None:
    main_module.app.dependency_overrides.pop(main_module.require_allowed_origin)
    accepted: list[tuple[str, str]] = []

    def accept_invitation(token_hash: str, password_hash: str, *, now: datetime) -> bool:
        accepted.append((token_hash, password_hash))
        return True

    monkeypatch.setattr(
        main_module.auth_database,
        "accept_user_invitation",
        accept_invitation,
    )

    response = TestClient(main_module.app).post(
        "/api/auth/invitations/accept",
        headers={"Origin": main_module.settings.web_origin},
        json={"token": "x" * 43, "password": "a-secure-password"},
    )

    assert response.status_code == 204
    assert len(accepted[0][0]) == 64
    assert accepted[0][1] != "a-secure-password"


def test_create_scan_accepts_zip_and_returns_camel_case_progress(
    fake_repository: FakeRepository,
) -> None:
    response = TestClient(main_module.app).post(
        "/api/scans",
        data={"projectId": "payments-api"},
        files={"source": ("source.zip", b"PK-test", "application/zip")},
    )

    assert response.status_code == 202
    assert response.json()["projectId"] == "payments-api"
    assert response.json()["archiveName"] == "source.zip"
    assert response.json()["progressPercent"] is None
    assert fake_repository.created is not None
    assert fake_repository.created[2:] == ("source.zip", b"PK-test")

    history = TestClient(main_module.app).get("/api/projects/payments-api/scans")
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["items"][0]["status"] == "PENDING"


def test_create_scan_rejects_non_zip_upload(fake_repository: FakeRepository) -> None:
    response = TestClient(main_module.app).post(
        "/api/scans",
        data={"projectId": "payments-api"},
        files={"source": ("source.tar", b"data", "application/x-tar")},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "ZIP 형식의 파일만 업로드할 수 있습니다."}
    assert fake_repository.created is None


def test_create_scan_rejects_whitespace_project_id(fake_repository: FakeRepository) -> None:
    response = TestClient(main_module.app).post(
        "/api/scans",
        data={"projectId": "   "},
        files={"source": ("source.zip", b"PK-test", "application/zip")},
    )

    assert response.status_code == 400
    assert fake_repository.created is None


def test_create_scan_rejects_unknown_project(fake_repository: FakeRepository) -> None:
    response = TestClient(main_module.app).post(
        "/api/scans",
        data={"projectId": "missing"},
        files={"source": ("source.zip", b"PK-test", "application/zip")},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "프로젝트를 찾을 수 없습니다."}


def test_project_crud_history_and_delete(fake_repository: FakeRepository) -> None:
    client = TestClient(main_module.app)
    created = client.post(
        "/api/projects",
        json={
            "name": "  New API  ",
            "description": "  demo  ",
            "assignedToViewer": True,
            "memberUserIds": ["user-b", "user-a", "user-a"],
        },
    )
    assert created.status_code == 201
    assert created.json()["name"] == "New API"
    project_id = created.json()["id"]
    assert fake_repository.project_member_ids[project_id] == ["user-a", "user-b"]

    listed = client.get("/api/projects", params={"limit": 1, "offset": 0})
    assert listed.status_code == 200
    assert listed.json()["limit"] == 1
    assert listed.json()["total"] == 2

    updated = client.put(
        f"/api/projects/{project_id}",
        json={
            "name": "Renamed",
            "description": "updated",
            "assignedToViewer": False,
            "memberUserIds": ["user-c"],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"
    assert fake_repository.project_member_ids[project_id] == ["user-c"]

    history = client.get(f"/api/projects/{project_id}/scans")
    assert history.status_code == 200
    assert history.json() == {"items": [], "total": 0, "limit": 20, "offset": 0}

    fake_repository.active_project_delete = True
    active = client.delete(f"/api/projects/{project_id}")
    assert active.status_code == 409
    assert active.json() == {"detail": "진행 중인 분석이 끝난 뒤 프로젝트를 삭제해 주세요."}

    fake_repository.active_project_delete = False
    deleted = client.delete(f"/api/projects/{project_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/projects/{project_id}").status_code == 404


def test_project_list_trims_and_forwards_query_and_language_filters(
    fake_repository: FakeRepository,
) -> None:
    current = fake_repository.projects["payments-api"]
    now = datetime.now(UTC)
    fake_repository.projects["payments-api"] = current.model_copy(
        update={
            "description": "Processes card payments",
            "latest_scan": ScanProgress(
                scan_id="52f03ca1-2434-40e3-9c3e-c0c598571cb8",
                project_id=current.id,
                archive_name="source.zip",
                status="COMPLETED",
                phase="COMPLETED",
                progress_percent=100,
                completed_units=1,
                total_units=1,
                message="complete",
                detected_languages=["Python"],
                created_at=now,
                updated_at=now,
            ),
        }
    )

    response = TestClient(main_module.app).get(
        "/api/projects",
        params={"query": "  card  ", "language": "  Python  "},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert [item["id"] for item in response.json()["items"]] == ["payments-api"]
    assert fake_repository.last_project_filters == ("card", "Python")


def test_project_list_rejects_unknown_language_filter(
    fake_repository: FakeRepository,
) -> None:
    response = TestClient(main_module.app).get("/api/projects", params={"language": "Ruby"})

    assert response.status_code == 422
    assert response.json() == {"detail": "지원하지 않는 언어 필터입니다."}
    assert fake_repository.last_project_filters is None


def test_protected_route_requires_a_session() -> None:
    main_module.app.dependency_overrides.pop(main_module.get_current_user)

    response = TestClient(main_module.app).get("/api/projects")

    assert response.status_code == 401
    assert response.json() == {"detail": "로그인이 필요합니다."}


def test_normal_user_project_list_is_filtered_by_membership(
    fake_repository: FakeRepository,
) -> None:
    user = authenticated_user()
    main_module.app.dependency_overrides[main_module.get_current_user] = lambda: user

    response = TestClient(main_module.app).get("/api/projects")

    assert response.status_code == 200
    assert fake_repository.last_member_user_id == user.id


def test_normal_user_cannot_mutate_projects(fake_repository: FakeRepository) -> None:
    user = authenticated_user()
    main_module.app.dependency_overrides[main_module.get_current_user] = lambda: user

    response = TestClient(main_module.app).post(
        "/api/projects",
        json={"name": "Blocked", "description": "read only account"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "관리자 권한이 필요합니다."}


def test_normal_user_cannot_open_an_unassigned_project(
    fake_repository: FakeRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = authenticated_user()
    main_module.app.dependency_overrides[main_module.get_current_user] = lambda: user
    monkeypatch.setattr(
        main_module.auth_database,
        "user_can_access_project",
        lambda _user_id, _project_id: False,
    )

    response = TestClient(main_module.app).get("/api/projects/payments-api")

    assert response.status_code == 404
    assert response.json() == {"detail": "프로젝트를 찾을 수 없습니다."}


def test_engine_contract_exposes_pinned_snapshot() -> None:
    response = TestClient(main_module.app).get("/api/engine")

    assert response.status_code == 200
    assert response.json()["engineName"] == "Semgrep"
    assert response.json()["engineVersion"] == "1.174.0"
    assert response.json()["registeredRuleCount"] == 86
    assert response.json()["executedRuleCount"] is None


def test_results_are_not_available_before_completion(fake_repository: FakeRepository) -> None:
    create_response = TestClient(main_module.app).post(
        "/api/scans",
        data={"projectId": "payments-api"},
        files={"source": ("source.zip", b"PK-test", "application/zip")},
    )
    scan_id = create_response.json()["scanId"]

    response = TestClient(main_module.app).get(f"/api/scans/{scan_id}/results")

    assert response.status_code == 409


def test_scan_path_rejects_invalid_uuid(fake_repository: FakeRepository) -> None:
    response = TestClient(main_module.app).get("/api/scans/not-a-uuid")

    assert response.status_code == 422


def test_scan_files_exposes_lazy_metadata_only_contract(
    fake_repository: FakeRepository,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    fake_repository.file_list = ScanFileList(
        scan_id=scan_id,
        manifest_available=True,
        manifest_version=1,
        parent_path=None,
        items=[
            ScanFileNode(
                path="src",
                parent_path=None,
                name="src",
                depth=1,
                entry_type="DIRECTORY",
                size_bytes=None,
                language=None,
                analysis_state="DIRECTORY",
                finding_count=2,
                has_children=True,
            )
        ],
        next_cursor="opaque-cursor",
    )

    response = TestClient(main_module.app).get(f"/api/scans/{scan_id}/files", params={"limit": 1})

    assert response.status_code == 200
    assert response.json() == {
        "scanId": scan_id,
        "manifestAvailable": True,
        "manifestVersion": 1,
        "unavailableReason": None,
        "parentPath": None,
        "items": [
            {
                "path": "src",
                "parentPath": None,
                "name": "src",
                "depth": 1,
                "entryType": "DIRECTORY",
                "sizeBytes": None,
                "language": None,
                "analysisState": "DIRECTORY",
                "findingCount": 2,
                "hasChildren": True,
            }
        ],
        "nextCursor": "opaque-cursor",
    }
    assert "source" not in response.text.casefold()
    assert "archive" not in response.text.casefold()


def test_scan_files_returns_legacy_unavailable_contract(
    fake_repository: FakeRepository,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"

    response = TestClient(main_module.app).get(f"/api/scans/{scan_id}/files")

    assert response.status_code == 200
    assert response.json()["manifestAvailable"] is False
    assert response.json()["manifestVersion"] is None
    assert response.json()["unavailableReason"] == "LEGACY_SCAN"


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (ScanFilesNotReadyError(), 409),
        (ScanFileParentNotFoundError(), 404),
        (InvalidScanFilesCursorError(), 400),
        (CorruptScanManifestError(), 500),
    ],
)
def test_scan_files_maps_repository_fail_closed_errors(
    fake_repository: FakeRepository, error: Exception, expected_status: int
) -> None:
    fake_repository.files_error = error

    response = TestClient(main_module.app).get(
        "/api/scans/52f03ca1-2434-40e3-9c3e-c0c598571cb8/files"
    )

    assert response.status_code == expected_status


def test_scan_issue_routes_expose_source_free_contract_and_bound_filters(
    fake_repository: FakeRepository,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    issue_id = "2278683e-1af4-5680-b8b0-db119a3b68f2"
    fingerprint = "b5b8f15446ce6d34c6d1c1c694df53b8b252a8974cc05a2745a2cc821d528621"
    item = IssueListItem(
        issue_id=issue_id,
        fingerprint=fingerprint,
        fingerprint_version=1,
        result_status="DETECTED",
        finding_kind="DETECTED",
        detection_basis_version=1,
        confidence="MEDIUM",
        detection_rationale="저장된 규칙 설명과 메시지에 따른 자동 탐지 근거입니다.",
        severity="ERROR",
        weakness_id="KISA-2021-02",
        weakness_number=2,
        weakness_name="코드 삽입",
        implementation_status="PARTIALLY_IMPLEMENTED",
        rule_id="kisa-2021-02-python-code-injection",
        language="Python",
        path="src/app.py",
        start_line=1,
        start_column=1,
        end_line=1,
        end_column=5,
        message="dynamic execution",
    )
    fake_repository.issue_list = IssueList(
        scan_id=scan_id,
        issue_model_available=True,
        items=[item],
        total=1,
        limit=1,
        stats=IssueStats(
            total_issue_count=1,
            detected_issue_count=1,
            review_signal_count=0,
            severity_counts=IssueSeverityCounts(error=1, warning=0, info=0),
        ),
    )
    fake_repository.issue_detail = IssueDetail(
        scan_id=scan_id,
        issue_id=issue_id,
        fingerprint=fingerprint,
        fingerprint_version=1,
        result_status="DETECTED",
        finding_kind="DETECTED",
        detection_basis_version=1,
        confidence="MEDIUM",
        detection_rationale="저장된 규칙 설명과 메시지에 따른 자동 탐지 근거입니다.",
        weakness=IssueWeaknessSnapshot(
            weakness_id="KISA-2021-02",
            number=2,
            category="입력데이터 검증 및 표현",
            category_number=1,
            name="코드 삽입",
            description="description",
            sast_classification="PARTIAL",
            implementation_status="PARTIALLY_IMPLEMENTED",
        ),
        rule=IssueRuleSnapshot(
            rule_id="kisa-2021-02-python-code-injection",
            language="Python",
            severity="ERROR",
            message="dynamic execution",
        ),
        location=IssueLocation(
            path="src/app.py", start_line=1, start_column=1, end_line=1, end_column=5
        ),
        engine_snapshot=EngineSnapshot(
            engine_name="Semgrep",
            engine_version="1.174.0",
            rulepack_name="KISA 2021 SAST",
            rulepack_version="kisa-2021-v2",
            ruleset_digest="a" * 64,
            registered_rule_count=86,
            executed_rule_count=27,
        ),
        evidence=IssueEvidence(),
        automation_limitation="정적 규칙은 실제 실행 경로를 확인하지 않습니다.",
        manual_verification_checks=["외부 입력 도달성을 확인합니다."],
        remediation="허용 목록 검증과 안전한 전용 API를 적용합니다.",
        safe_implementation_example="개념 예시(원본 코드 아님): validated = require_allowed(value)",
        references=["https://cwe.mitre.org/data/index.html"],
    )

    client = TestClient(main_module.app)
    listed = client.get(
        f"/api/scans/{scan_id}/issues",
        params={
            "status": "DETECTED",
            "severity": "ERROR",
            "language": "Python",
            "weaknessId": "KISA-2021-02",
            "path": "src/app.py",
            "pathScope": "FILE",
            "limit": 1,
        },
    )
    assert listed.status_code == 200
    assert listed.json()["items"][0]["issueId"] == issue_id
    assert listed.json()["items"][0]["detectionBasisVersion"] == 1
    assert listed.json()["items"][0]["confidence"] == "MEDIUM"
    assert listed.json()["items"][0]["detectionRationale"]
    assert listed.json()["stats"] == {
        "totalIssueCount": 1,
        "detectedIssueCount": 1,
        "reviewSignalCount": 0,
        "severityCounts": {"ERROR": 1, "WARNING": 0, "INFO": 0},
    }
    assert "source" not in listed.text.casefold()
    assert fake_repository.last_issue_filters is not None

    detail = client.get(f"/api/scans/{scan_id}/issues/{issue_id}")
    assert detail.status_code == 200
    assert detail.json()["evidence"] == {
        "available": False,
        "reason": "SOURCE_NOT_RETAINED",
    }
    assert detail.json()["detectionBasisVersion"] == 1
    assert detail.json()["confidence"] == "MEDIUM"
    assert detail.json()["detectionRationale"]
    assert detail.json()["automationLimitation"].startswith("정적 규칙")
    assert detail.json()["manualVerificationChecks"]
    assert detail.json()["safeImplementationExample"].startswith("개념 예시")
    assert detail.json()["references"] == ["https://cwe.mitre.org/data/index.html"]
    assert "snippet" not in detail.text.casefold()


def test_scan_coverage_route_exposes_v2_language_rows(
    fake_repository: FakeRepository,
) -> None:
    scan_id = "52f03ca1-2434-40e3-9c3e-c0c598571cb8"
    items = []
    for weakness in KISA_CATALOG:
        detected = weakness.number == 2
        supported = weakness.number == 2
        items.append(
            CoverageCriterionV2(
                weakness_id=weakness.weakness_id,
                number=weakness.number,
                category=weakness.category,
                category_number=weakness.category_number,
                name=weakness.name,
                description=weakness.description,
                sast_classification=weakness.sast_classification,
                implementation_status=weakness.implementation_status,
                reason="분석 대상 언어별 자동 탐지 결과를 확인하세요.",
                finding_count=1 if detected else 0,
                languages=[
                    LanguageCoverageResult(
                        language="Python",
                        support_status="SUPPORTED" if supported else "NOT_SUPPORTED",
                        result_status="DETECTED" if detected else "NOT_SUPPORTED",
                        executed_rule_count=1 if supported else 0,
                        finding_count=1 if detected else 0,
                        reason="검증된 룰 실행 결과입니다.",
                    )
                ],
            )
        )
    fake_repository.coverage = ScanCoverage(
        scan_id=scan_id,
        coverage_model_version=2,
        summary=CoverageSummaryV2(
            total_criterion_count=49,
            detected_criterion_count=1,
            not_detected_criterion_count=0,
            not_supported_criterion_count=48,
            total_language_result_count=49,
            total_finding_count=1,
            issue_stats=IssueStatsV2(
                total_issue_count=1,
                detected_issue_count=1,
                severity_counts=IssueSeverityCounts(error=1, warning=0, info=0),
            ),
        ),
        items=items,
    )

    response = TestClient(main_module.app).get(f"/api/scans/{scan_id}/coverage")

    assert response.status_code == 200
    payload = response.json()
    assert payload["coverageModelVersion"] == 2
    assert payload["summary"]["totalLanguageResultCount"] == 49
    assert "reviewRequiredCriterionCount" not in payload["summary"]
    assert "reviewSignalCount" not in payload["summary"]["issueStats"]
    assert payload["items"][1]["languages"] == [
        {
            "language": "Python",
            "supportStatus": "SUPPORTED",
            "resultStatus": "DETECTED",
            "executedRuleCount": 1,
            "findingCount": 1,
            "reason": "검증된 룰 실행 결과입니다.",
        }
    ]
    assert "supportStatus" not in payload["items"][1]
    assert payload["legacyNotice"] is None


@pytest.mark.parametrize(
    ("attribute", "error", "endpoint", "expected_status"),
    [
        ("issues_error", ScanIssuesNotReadyError(), "issues", 409),
        ("issues_error", InvalidIssueFilterError(), "issues", 400),
        ("issues_error", InvalidIssuesCursorError(), "issues", 400),
        ("issues_error", CorruptScanIssueModelError(), "issues", 500),
        (
            "issue_detail_error",
            ScanIssuesNotReadyError(),
            "issues/2278683e-1af4-5680-b8b0-db119a3b68f2",
            409,
        ),
        (
            "issue_detail_error",
            LegacyIssueModelUnavailableError(),
            "issues/2278683e-1af4-5680-b8b0-db119a3b68f2",
            409,
        ),
        (
            "issue_detail_error",
            CorruptScanIssueModelError(),
            "issues/2278683e-1af4-5680-b8b0-db119a3b68f2",
            500,
        ),
        ("coverage_error", ScanIssuesNotReadyError(), "coverage", 409),
        ("coverage_error", CorruptScanIssueModelError(), "coverage", 500),
    ],
)
def test_scan_issue_routes_map_repository_fail_closed_errors(
    fake_repository: FakeRepository,
    attribute: str,
    error: Exception,
    endpoint: str,
    expected_status: int,
) -> None:
    setattr(fake_repository, attribute, error)

    response = TestClient(main_module.app).get(
        f"/api/scans/52f03ca1-2434-40e3-9c3e-c0c598571cb8/{endpoint}"
    )

    assert response.status_code == expected_status


def test_list_rules_returns_all_kisa_catalog_fields() -> None:
    response = TestClient(main_module.app).get("/api/rules")

    assert response.status_code == 200
    rules = response.json()
    assert len(rules) == 49
    assert rules[0] == {
        "weaknessId": "KISA-2021-01",
        "number": 1,
        "category": "입력데이터 검증 및 표현",
        "categoryNumber": 1,
        "name": "SQL 삽입",
        "description": (
            "SQL 질의문을 생성할 때 검증되지 않은 외부 입력 값을 허용하여 악의적인 "
            "질의문이 실행가능한 보안약점"
        ),
        "sastClassification": "PARTIAL",
        "implementationStatus": "PARTIALLY_IMPLEMENTED",
    }


def test_list_rules_filters_by_identifier_category_name_and_status() -> None:
    client = TestClient(main_module.app)

    by_identifier = client.get("/api/rules", params={"identifier": "kisa-2021-49"})
    assert [item["weaknessId"] for item in by_identifier.json()] == ["KISA-2021-49"]

    by_category_and_name = client.get(
        "/api/rules",
        params={"category": "보안기능", "name": "암호화"},
    )
    assert [item["weaknessId"] for item in by_category_and_name.json()] == [
        "KISA-2021-21",
        "KISA-2021-22",
    ]

    by_status = client.get(
        "/api/rules",
        params={"implementation_status": "MANUAL_REVIEW_REQUIRED"},
    )
    assert by_status.status_code == 200
    assert by_status.json()
    assert {item["implementationStatus"] for item in by_status.json()} == {"MANUAL_REVIEW_REQUIRED"}


def test_list_rules_supports_general_query_and_item_number_filters() -> None:
    client = TestClient(main_module.app)

    by_query = client.get("/api/rules", params={"query": "레인보우 테이블"})
    assert [item["weaknessId"] for item in by_query.json()] == ["KISA-2021-31"]

    by_normalized_name = client.get("/api/rules", params={"query": "경쟁조건:"})
    assert [item["weaknessId"] for item in by_normalized_name.json()] == ["KISA-2021-34"]

    by_global_number = client.get("/api/rules", params={"number": 34})
    assert [item["weaknessId"] for item in by_global_number.json()] == ["KISA-2021-34"]

    by_category_number = client.get(
        "/api/rules",
        params={"category": "API 오용", "category_number": 2},
    )
    assert [item["weaknessId"] for item in by_category_number.json()] == ["KISA-2021-49"]


def test_list_rules_rejects_unknown_implementation_status() -> None:
    response = TestClient(main_module.app).get(
        "/api/rules",
        params={"implementation_status": "DONE"},
    )

    assert response.status_code == 422
