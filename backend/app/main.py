from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from psycopg import connect

from app.auth import (
    SESSION_COOKIE_NAME,
    hash_invitation_token,
    hash_password,
    hash_session_token,
    is_valid_email,
    new_invitation_token,
    new_session_token,
    normalize_email,
    verify_password,
)
from app.catalog import KISA_CATALOG, ImplementationStatus, Weakness
from app.config import get_settings
from app.database import (
    CorruptScanIssueModelError,
    CorruptScanManifestError,
    Database,
    InvalidIssueFilterError,
    InvalidIssuesCursorError,
    InvalidProjectMembersError,
    InvalidScanFilesCursorError,
    IssueFilters,
    LegacyIssueModelUnavailableError,
    ProjectHasActiveScansError,
    ProjectNotFoundError,
    ScanFileParentNotFoundError,
    ScanFilesNotReadyError,
    ScanIssuesNotReadyError,
    ScanRepository,
    UserEmailAlreadyExistsError,
)
from app.engine import ENGINE_NAME, ENGINE_VERSION, RULEPACK_NAME
from app.http_limits import RequestBodyLimitMiddleware
from app.mailer import send_invitation_email
from app.rule_registry import RULE_REGISTRY, RULEPACK_VERSION, RULESET_DIGEST
from app.schemas import (
    AuthenticatedUser,
    EngineSnapshot,
    InvitationAcceptRequest,
    IssueDetail,
    IssueList,
    IssuePathScope,
    IssueSeverity,
    LoginRequest,
    Project,
    ProjectCreate,
    ProjectList,
    ProjectMemberList,
    ProjectMembersUpdate,
    ProjectUpdate,
    ScanCoverage,
    ScanFileList,
    ScanList,
    ScanProgress,
    ScanResults,
    UserInviteRequest,
    UserList,
    UserRole,
    UserSummary,
    UserUpdate,
    WeaknessCatalogItem,
)

settings = get_settings()
repository: ScanRepository = Database(settings.database_url, cursor_secret=settings.session_secret)
auth_database = Database(settings.database_url, cursor_secret=settings.session_secret)
SUPPORTED_PROJECT_LANGUAGES = frozenset({"Java", "JavaScript", "Python"})

app = FastAPI(
    title="TOY SAST API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.web_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)
app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_request_body_bytes)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict[str, str]:
    try:
        with connect(settings.database_url, connect_timeout=2) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        Database(settings.database_url).ensure_schema()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ready"}


def get_current_user(
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> AuthenticatedUser:
    if not session_token:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    user = auth_database.get_authenticated_user(
        hash_session_token(session_token, settings.session_secret), now=datetime.now(UTC)
    )
    if user is None:
        raise HTTPException(status_code=401, detail="세션이 만료되었거나 유효하지 않습니다.")
    return user


def require_admin(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> AuthenticatedUser:
    if user.role is not UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return user


def require_allowed_origin(request: Request) -> None:
    if request.headers.get("origin") != settings.web_origin:
        raise HTTPException(status_code=403, detail="허용되지 않은 요청 출처입니다.")


def _ensure_project_access(user: AuthenticatedUser, project_id: str) -> None:
    if user.role is UserRole.ADMIN:
        return
    if not auth_database.user_can_access_project(user.id, project_id):
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")


def _authorized_scan(user: AuthenticatedUser, scan_id: str) -> ScanProgress:
    scan = repository.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="분석 작업을 찾을 수 없습니다.")
    _ensure_project_access(user, scan.project_id)
    return scan


def _ensure_scan_access(user: AuthenticatedUser, scan_id: str) -> None:
    if user.role is UserRole.ADMIN:
        return
    _authorized_scan(user, scan_id)


@app.post("/api/auth/login", response_model=AuthenticatedUser)
def login(
    payload: LoginRequest,
    response: Response,
    _: Annotated[None, Depends(require_allowed_origin)],
) -> AuthenticatedUser:
    email = normalize_email(payload.email)
    credentials = auth_database.get_user_credentials_by_email(email)
    password_valid = verify_password(
        credentials.password_hash if credentials is not None else None, payload.password
    )
    if credentials is None or not credentials.is_active or not password_valid:
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다.")
    token = new_session_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.session_absolute_ttl_seconds)
    user = auth_database.create_session(
        hash_session_token(token, settings.session_secret),
        credentials.id,
        expires_at=expires_at,
    )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=settings.session_absolute_ttl_seconds,
        httponly=True,
        secure=settings.app_env != "local",
        samesite="strict",
        path="/",
    )
    return user


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    _: Annotated[None, Depends(require_allowed_origin)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> Response:
    if session_token:
        auth_database.delete_session(hash_session_token(session_token, settings.session_secret))
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", samesite="strict")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/api/auth/me", response_model=AuthenticatedUser)
def get_me(user: Annotated[AuthenticatedUser, Depends(get_current_user)]) -> AuthenticatedUser:
    return user


@app.post("/api/auth/invitations/accept", status_code=status.HTTP_204_NO_CONTENT)
def accept_invitation(
    payload: InvitationAcceptRequest,
    _: Annotated[None, Depends(require_allowed_origin)],
) -> Response:
    accepted = auth_database.accept_user_invitation(
        hash_invitation_token(payload.token, settings.session_secret),
        hash_password(payload.password),
        now=datetime.now(UTC),
    )
    if not accepted:
        raise HTTPException(status_code=400, detail="초대 링크가 만료되었거나 이미 사용되었습니다.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/admin/users", response_model=UserList)
def list_users(_: Annotated[AuthenticatedUser, Depends(require_admin)]) -> UserList:
    return auth_database.list_users()


@app.post(
    "/api/admin/users/invitations",
    response_model=UserSummary,
    status_code=status.HTTP_201_CREATED,
)
def invite_user(
    payload: UserInviteRequest,
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> UserSummary:
    email = normalize_email(payload.email)
    if not is_valid_email(email):
        raise HTTPException(status_code=422, detail="올바른 이메일 주소를 입력해 주세요.")
    token = new_invitation_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.invitation_ttl_seconds)
    try:
        user = auth_database.save_user_invitation(
            str(uuid4()),
            email=email,
            token_hash=hash_invitation_token(token, settings.session_secret),
            expires_at=expires_at,
        )
    except UserEmailAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail="이미 등록된 이메일입니다.") from exc
    invitation_url = f"{settings.web_origin}/accept-invite?token={token}"
    try:
        send_invitation_email(
            smtp_host=settings.smtp_host,
            smtp_port=settings.smtp_port,
            mail_from=settings.mail_from,
            recipient=email,
            invitation_url=invitation_url,
        )
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail="초대 메일을 보내지 못했습니다. 메일 서버 상태를 확인한 뒤 다시 시도해 주세요.",
        ) from exc
    return user


@app.patch("/api/admin/users/{user_id}", response_model=UserSummary)
def update_user(
    user_id: UUID,
    payload: UserUpdate,
    _admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> UserSummary:
    user = auth_database.set_user_active(str(user_id), payload.is_active)
    if user is None:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    return user


@app.get("/api/projects/{project_id}/members", response_model=ProjectMemberList)
def list_project_members(
    project_id: str,
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
) -> ProjectMemberList:
    user_ids = auth_database.list_project_member_ids(project_id)
    if user_ids is None:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    return ProjectMemberList(user_ids=user_ids)


@app.put("/api/projects/{project_id}/members", response_model=ProjectMemberList)
def update_project_members(
    project_id: str,
    payload: ProjectMembersUpdate,
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> ProjectMemberList:
    try:
        updated = auth_database.replace_project_members(project_id, payload.user_ids)
    except InvalidProjectMembersError as exc:
        raise HTTPException(
            status_code=422, detail="할당할 수 없는 사용자가 포함되어 있습니다."
        ) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    return ProjectMemberList(user_ids=sorted(set(payload.user_ids)))


@app.get("/api/engine", response_model=EngineSnapshot)
def get_engine(_: Annotated[AuthenticatedUser, Depends(get_current_user)]) -> EngineSnapshot:
    return EngineSnapshot(
        engine_name=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        rulepack_name=RULEPACK_NAME,
        rulepack_version=RULEPACK_VERSION,
        ruleset_digest=RULESET_DIGEST,
        registered_rule_count=len(RULE_REGISTRY),
        executed_rule_count=None,
    )


@app.get("/api/projects", response_model=ProjectList)
def list_projects(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    query: Annotated[str | None, Query(max_length=200)] = None,
    language: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectList:
    normalized_language = language.strip() if language else None
    if normalized_language and normalized_language not in SUPPORTED_PROJECT_LANGUAGES:
        raise HTTPException(status_code=422, detail="지원하지 않는 언어 필터입니다.")
    return repository.list_projects(
        query=query.strip() if query else None,
        language=normalized_language,
        member_user_id=user.id if user.role is UserRole.USER else None,
        limit=limit,
        offset=offset,
    )


@app.post("/api/projects", response_model=Project, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> Project:
    normalized = _normalize_project_payload(payload, ProjectCreate)
    try:
        return repository.create_project(normalized)
    except InvalidProjectMembersError as exc:
        raise HTTPException(
            status_code=422, detail="할당할 수 없는 사용자가 포함되어 있습니다."
        ) from exc


@app.get("/api/projects/{project_id}", response_model=Project)
def get_project(
    project_id: str, user: Annotated[AuthenticatedUser, Depends(get_current_user)]
) -> Project:
    _ensure_project_access(user, project_id)
    project = repository.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    return project


@app.put("/api/projects/{project_id}", response_model=Project)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> Project:
    normalized = _normalize_project_payload(payload, ProjectUpdate)
    try:
        project = repository.update_project(project_id, normalized)
    except InvalidProjectMembersError as exc:
        raise HTTPException(
            status_code=422, detail="할당할 수 없는 사용자가 포함되어 있습니다."
        ) from exc
    if project is None:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    return project


@app.delete("/api/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: str,
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> Response:
    try:
        deleted = repository.delete_project(project_id)
    except ProjectHasActiveScansError as exc:
        raise HTTPException(
            status_code=409,
            detail="진행 중인 분석이 끝난 뒤 프로젝트를 삭제해 주세요.",
        ) from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/projects/{project_id}/scans", response_model=ScanList)
def list_project_scans(
    project_id: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanList:
    _ensure_project_access(user, project_id)
    try:
        return repository.list_project_scans(project_id, limit=limit, offset=offset)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.") from exc


def _normalize_project_payload[ProjectPayload: (ProjectCreate, ProjectUpdate)](
    payload: ProjectPayload, model: type[ProjectPayload]
) -> ProjectPayload:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="프로젝트 이름을 입력해 주세요.")
    return model(
        name=name,
        description=payload.description.strip(),
        assigned_to_viewer=payload.assigned_to_viewer,
        member_user_ids=payload.member_user_ids,
    )


@app.get("/api/rules", response_model=list[WeaknessCatalogItem])
def list_rules(
    _: Annotated[AuthenticatedUser, Depends(get_current_user)],
    query: Annotated[str | None, Query(max_length=200)] = None,
    identifier: Annotated[str | None, Query(max_length=32)] = None,
    category: Annotated[str | None, Query(max_length=80)] = None,
    number: Annotated[int | None, Query(ge=1, le=49)] = None,
    category_number: Annotated[int | None, Query(ge=1)] = None,
    name: Annotated[str | None, Query(max_length=120)] = None,
    implementation_status: Annotated[ImplementationStatus | None, Query()] = None,
) -> list[WeaknessCatalogItem]:
    normalized_query = _normalize_filter(query)
    normalized_identifier = _normalize_filter(identifier)
    normalized_category = _normalize_filter(category)
    normalized_name = _normalize_filter(name)
    matches: list[WeaknessCatalogItem] = []
    for weakness in KISA_CATALOG:
        if normalized_identifier and weakness.weakness_id.casefold() != normalized_identifier:
            continue
        if normalized_category and weakness.category.casefold() != normalized_category:
            continue
        if number is not None and weakness.number != number:
            continue
        if category_number is not None and weakness.category_number != category_number:
            continue
        if normalized_name and normalized_name not in weakness.name.casefold():
            continue
        if (
            implementation_status is not None
            and weakness.implementation_status is not implementation_status
        ):
            continue
        if normalized_query and not _matches_catalog_query(normalized_query, weakness):
            continue
        matches.append(WeaknessCatalogItem.model_validate(weakness, from_attributes=True))
    return matches


def _normalize_filter(value: str | None) -> str:
    return value.strip().casefold() if value else ""


def _catalog_search_text(weakness: Weakness) -> str:
    item = WeaknessCatalogItem.model_validate(weakness, from_attributes=True)
    return " ".join(
        (
            item.weakness_id,
            str(item.number),
            item.category,
            str(item.category_number),
            item.name,
            item.description,
            item.sast_classification,
            item.implementation_status.value,
        )
    ).casefold()


def _matches_catalog_query(query: str, weakness: Weakness) -> bool:
    search_text = _catalog_search_text(weakness)
    if query in search_text:
        return True
    return "".join(query.split()) in "".join(search_text.split())


@app.post("/api/scans", response_model=ScanProgress, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    project_id: Annotated[str, Form(alias="projectId", min_length=1, max_length=120)],
    source: Annotated[UploadFile, File()],
    _: Annotated[AuthenticatedUser, Depends(require_admin)],
    _origin: Annotated[None, Depends(require_allowed_origin)],
) -> ScanProgress:
    normalized_project_id = project_id.strip()
    if not normalized_project_id:
        await source.close()
        raise HTTPException(status_code=400, detail="프로젝트 식별자를 입력해 주세요.")
    filename = Path(source.filename or "").name
    if not filename.lower().endswith(".zip"):
        await source.close()
        raise HTTPException(status_code=400, detail="ZIP 형식의 파일만 업로드할 수 있습니다.")

    try:
        archive_data = await source.read(settings.max_upload_bytes + 1)
    finally:
        await source.close()
    if not archive_data:
        raise HTTPException(status_code=400, detail="비어 있는 ZIP 파일은 업로드할 수 없습니다.")
    if len(archive_data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="ZIP 파일 크기가 허용 범위를 초과합니다.",
        )

    try:
        return repository.create_scan(str(uuid4()), normalized_project_id, filename, archive_data)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.") from exc


@app.get("/api/scans/{scan_id}", response_model=ScanProgress)
def get_scan(
    scan_id: UUID, user: Annotated[AuthenticatedUser, Depends(get_current_user)]
) -> ScanProgress:
    return _authorized_scan(user, str(scan_id))


@app.get("/api/scans/{scan_id}/results", response_model=ScanResults)
def get_scan_results(
    scan_id: UUID, user: Annotated[AuthenticatedUser, Depends(get_current_user)]
) -> ScanResults:
    normalized_scan_id = str(scan_id)
    scan = _authorized_scan(user, normalized_scan_id)
    if scan.status != "COMPLETED":
        raise HTTPException(status_code=409, detail="분석이 아직 완료되지 않았습니다.")
    results = repository.get_results(normalized_scan_id)
    if results is None:
        raise HTTPException(status_code=500, detail="분석 결과를 불러오지 못했습니다.")
    return results


@app.get("/api/scans/{scan_id}/issues", response_model=IssueList)
def get_scan_issues(
    scan_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    result_status: Annotated[str | None, Query(alias="status", min_length=1, max_length=32)] = None,
    severity: Annotated[IssueSeverity | None, Query()] = None,
    language: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    weakness_id: Annotated[
        str | None, Query(alias="weaknessId", min_length=1, max_length=32)
    ] = None,
    path: Annotated[str | None, Query(min_length=1, max_length=4096)] = None,
    path_scope: Annotated[IssuePathScope | None, Query(alias="pathScope")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=8192)] = None,
) -> IssueList:
    _ensure_scan_access(user, str(scan_id))
    try:
        issues = repository.get_scan_issues(
            str(scan_id),
            filters=IssueFilters(
                result_status=result_status,
                severity=severity.value if severity is not None else None,
                language=language,
                weakness_id=weakness_id,
                path=path,
                path_scope=path_scope,
            ),
            limit=limit,
            cursor=cursor,
        )
    except (InvalidIssueFilterError, InvalidIssuesCursorError) as exc:
        raise HTTPException(
            status_code=400, detail="이슈 필터 또는 cursor가 올바르지 않습니다."
        ) from exc
    except ScanIssuesNotReadyError as exc:
        raise HTTPException(status_code=409, detail="분석이 아직 완료되지 않았습니다.") from exc
    except CorruptScanIssueModelError as exc:
        raise HTTPException(
            status_code=500, detail="이슈 결과를 안전하게 불러오지 못했습니다."
        ) from exc
    if issues is None:
        raise HTTPException(status_code=404, detail="분석 작업을 찾을 수 없습니다.")
    return issues


@app.get("/api/scans/{scan_id}/issues/{issue_id}", response_model=IssueDetail)
def get_scan_issue(
    scan_id: UUID,
    issue_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> IssueDetail:
    _ensure_scan_access(user, str(scan_id))
    try:
        issue = repository.get_scan_issue(str(scan_id), str(issue_id))
    except ScanIssuesNotReadyError as exc:
        raise HTTPException(status_code=409, detail="분석이 아직 완료되지 않았습니다.") from exc
    except LegacyIssueModelUnavailableError as exc:
        raise HTTPException(
            status_code=409, detail="이전 분석에는 이슈 상세 모델이 없습니다."
        ) from exc
    except CorruptScanIssueModelError as exc:
        raise HTTPException(
            status_code=500, detail="이슈 상세를 안전하게 불러오지 못했습니다."
        ) from exc
    if issue is None:
        raise HTTPException(status_code=404, detail="이슈를 찾을 수 없습니다.")
    return issue


@app.get("/api/scans/{scan_id}/coverage", response_model=ScanCoverage)
def get_scan_coverage(
    scan_id: UUID, user: Annotated[AuthenticatedUser, Depends(get_current_user)]
) -> ScanCoverage:
    _ensure_scan_access(user, str(scan_id))
    try:
        coverage = repository.get_scan_coverage(str(scan_id))
    except ScanIssuesNotReadyError as exc:
        raise HTTPException(status_code=409, detail="분석이 아직 완료되지 않았습니다.") from exc
    except (CorruptScanIssueModelError, ValueError) as exc:
        raise HTTPException(
            status_code=500, detail="검사 기준 결과를 안전하게 불러오지 못했습니다."
        ) from exc
    if coverage is None:
        raise HTTPException(status_code=404, detail="분석 작업을 찾을 수 없습니다.")
    return coverage


@app.get("/api/scans/{scan_id}/files", response_model=ScanFileList)
def get_scan_files(
    scan_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    parent_path: Annotated[
        str | None, Query(alias="parentPath", min_length=1, max_length=4096)
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    cursor: Annotated[str | None, Query(min_length=1, max_length=8192)] = None,
) -> ScanFileList:
    _ensure_scan_access(user, str(scan_id))
    try:
        files = repository.get_scan_files(
            str(scan_id),
            parent_path=parent_path,
            limit=limit,
            cursor=cursor,
        )
    except ScanFilesNotReadyError as exc:
        raise HTTPException(status_code=409, detail="분석이 아직 완료되지 않았습니다.") from exc
    except ScanFileParentNotFoundError as exc:
        raise HTTPException(status_code=404, detail="파일 트리 경로를 찾을 수 없습니다.") from exc
    except InvalidScanFilesCursorError as exc:
        raise HTTPException(
            status_code=400, detail="파일 목록 cursor가 올바르지 않습니다."
        ) from exc
    except CorruptScanManifestError as exc:
        raise HTTPException(
            status_code=500, detail="파일 manifest를 안전하게 불러오지 못했습니다."
        ) from exc
    if files is None:
        raise HTTPException(status_code=404, detail="분석 작업을 찾을 수 없습니다.")
    return files
