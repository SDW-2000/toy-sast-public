import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from './App';
import type { FileManifestPage, IssueDetail, IssueList, Project, ScanCoverage, ScanProgress } from './domain';
import { demoCoverage } from './fixtures';

const scan: ScanProgress = { scanId: '11111111-1111-4111-8111-111111111111', projectId: 'payment-api', archiveName: 'payment-api.zip', status: 'COMPLETED', phase: 'COMPLETED', progressPercent: 100, completedUnits: 79, totalUnits: 79, archiveFileCount: 20, analysisFileCount: 12, detectedLanguages: ['Java', 'JavaScript'], languageFileCounts: { Java: 8, JavaScript: 4 }, engineSnapshot: { engineName: 'Semgrep', engineVersion: '1.174.0', rulepackName: 'KISA 2021', rulepackVersion: 'kisa-2021-v2', rulesetDigest: 'digest', registeredRuleCount: 86, executedRuleCount: 79 }, createdAt: '2026-08-29T00:00:00Z', updatedAt: '2026-08-29T00:01:00Z', message: '완료' };
const project: Project = { id: scan.projectId, name: '결제 API', description: '결제 서비스', assignedToViewer: true, createdAt: scan.createdAt, updatedAt: scan.updatedAt, latestScan: scan };
const issues: IssueList = { scanId: scan.scanId, issueModelAvailable: true, unavailableReason: null, total: 2, limit: 50, nextCursor: 'second-page', stats: { totalIssueCount: 2, detectedIssueCount: 1, reviewSignalCount: 1, severityCounts: { ERROR: 1, WARNING: 0, INFO: 0 } }, items: [{ issueId: 'issue-a', fingerprint: 'a'.repeat(64), fingerprintVersion: 1, detectionBasisVersion: 1, resultStatus: 'DETECTED', findingKind: 'DETECTED', severity: 'ERROR', confidence: 'MEDIUM', detectionRationale: '외부 입력이 명령 실행 API에 전달되는 패턴이 일치했습니다.', weaknessId: 'KISA-2021-05', weaknessNumber: 5, weaknessName: '운영체제 명령어 삽입', implementationStatus: 'PARTIALLY_IMPLEMENTED', ruleId: 'rule-a', language: 'Java', path: 'src/App.java', startLine: 22, startColumn: 1, endLine: 22, endColumn: 10, message: 'message' }, { issueId: 'issue-b', fingerprint: 'b'.repeat(64), fingerprintVersion: 1, detectionBasisVersion: 1, resultStatus: 'REVIEW_REQUIRED', findingKind: 'REVIEW_SIGNAL', severity: 'WARNING', confidence: 'LOW', detectionRationale: '자동 확정이 불가능한 메모리 사용 패턴이 있어 수동 검토가 필요합니다.', weaknessId: 'KISA-2021-16', weaknessNumber: 16, weaknessName: '메모리 버퍼 오버플로우', implementationStatus: 'MANUAL_REVIEW_REQUIRED', ruleId: 'rule-b', language: 'JavaScript', path: 'web/code.js', startLine: 9, startColumn: 1, endLine: 9, endColumn: 3, message: 'review' }] };
const coverage: ScanCoverage = { scanId: scan.scanId, coverageModelVersion: 1, totalWeaknessCount: 49, summary: { totalCriterionCount: 49, detectedCriterionCount: 1, reviewRequiredCriterionCount: 1, notDetectedCriterionCount: 40, notSupportedCriterionCount: 7, totalFindingCount: 2, issueStats: issues.stats }, items: [{ weaknessId: 'KISA-2021-05', number: 5, category: '입력', categoryNumber: 5, name: '운영체제 명령어 삽입', description: null, sastClassification: 'AUTO', implementationStatus: 'PARTIALLY_IMPLEMENTED', supportStatus: 'PARTIALLY_SUPPORTED', resultStatus: 'DETECTED', reason: 'reason', findingCount: 1 }] };
const detail: IssueDetail = { scanId: scan.scanId, issueId: 'issue-a', fingerprint: 'a'.repeat(64), fingerprintVersion: 1, detectionBasisVersion: 1, resultStatus: 'DETECTED', findingKind: 'DETECTED', confidence: 'MEDIUM', detectionRationale: '외부 입력이 명령 실행 API에 전달되는 패턴이 일치했습니다.', weakness: { weaknessId: 'KISA-2021-05', number: 5, category: '입력', categoryNumber: 5, name: '운영체제 명령어 삽입', description: '설명', sastClassification: 'AUTO', implementationStatus: 'PARTIALLY_IMPLEMENTED' }, rule: { ruleId: 'rule-a', language: 'Java', severity: 'ERROR', message: 'external input', description: null, cweId: 'CWE-78' }, location: { path: 'src/App.java', startLine: 22, startColumn: 1, endLine: 22, endColumn: 10 }, engineSnapshot: scan.engineSnapshot!, evidence: { available: false, reason: 'SOURCE_NOT_RETAINED' }, automationLimitation: '정적 규칙은 실제 실행 경로를 자동으로 확인하지 않습니다.', manualVerificationChecks: ['외부 입력 도달성을 확인합니다.', '방어 로직을 확인합니다.'], remediation: '허용 목록 검증과 안전한 API를 적용합니다.', safeImplementationExample: '개념 예시(원본 코드 아님): validator.requireAllowed(value)', references: ['https://cwe.mitre.org/data/definitions/78.html'] };
const files: FileManifestPage = { scanId: scan.scanId, manifestAvailable: true, manifestVersion: 1, unavailableReason: null, parentPath: null, nextCursor: null, items: [{ path: 'src', parentPath: null, name: 'src', depth: 1, entryType: 'DIRECTORY', sizeBytes: null, language: null, analysisState: 'DIRECTORY', findingCount: 1, hasChildren: true }] };
let testRole: 'ADMIN' | 'USER' = 'ADMIN';
const authenticatedUser = () => ({ id: `${testRole.toLowerCase()}-user`, email: `${testRole.toLowerCase()}@toy-sast.local`, role: testRole, isActive: true, invitationPending: false, createdAt: scan.createdAt, updatedAt: scan.updatedAt, sessionExpiresAt: new Date(Date.now() + 60 * 60_000).toISOString() });

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
type ApiOverride = (url: URL, init?: RequestInit) => Response | undefined;

function mockApi(override: ApiOverride = () => undefined) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = new URL(String(input));
    const handled = override(url, init);
    if (handled) return handled;
    if (url.pathname === '/api/auth/me') return json(authenticatedUser());
    if (url.pathname === '/api/auth/logout') return new Response(null, { status: 204 });
    if (url.pathname === '/api/admin/users') return json({ items: [] });
    if (url.pathname.endsWith('/members')) return json({ userIds: [] });
    if (url.pathname === '/api/projects') return json({ items: [project], total: 1, limit: 100, offset: 0 });
    if (url.pathname === `/api/projects/${scan.projectId}`) return json(project);
    if (url.pathname === `/api/projects/${scan.projectId}/scans`) return json({ items: [scan], total: 1, limit: 20, offset: Number(url.searchParams.get('offset') ?? 0) });
    if (url.pathname === '/api/engine') return json(scan.engineSnapshot);
    if (url.pathname === `/api/scans/${scan.scanId}`) return json(scan);
    if (url.pathname === `/api/scans/${scan.scanId}/issues`) return json(issues);
    if (url.pathname === `/api/scans/${scan.scanId}/issues/issue-a`) return json(detail);
    if (url.pathname === `/api/scans/${scan.scanId}/coverage`) return json(coverage);
    if (url.pathname === `/api/scans/${scan.scanId}/files`) return json(files);
    return json({ detail: `Unhandled: ${url.pathname}` }, 404);
  });
}

function renderApp(path: string, role: 'ADMIN' | 'USER' = 'ADMIN', analysisStarted = false, verifySession = false) {
  testRole = role;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const entry = analysisStarted ? { pathname: path, state: { analysisStarted: true } } : path;
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><App initialUser={verifySession ? undefined : authenticatedUser()} /></MemoryRouter></QueryClientProvider>);
}

function wasRequested(fetchMock: ReturnType<typeof mockApi>, pathname: string) {
  return fetchMock.mock.calls.some(([input]) => new URL(String(input)).pathname === pathname);
}

async function flushAsyncWork() {
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
}

async function flushImmediateTimers() {
  for (let index = 0; index < 8; index += 1) {
    await flushAsyncWork();
    await vi.advanceTimersByTimeAsync(1);
  }
  await flushAsyncWork();
}

beforeEach(() => { testRole = 'ADMIN'; });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe('user invitation', () => {
  it('keeps the invitation form available when an admin session already exists', async () => {
    mockApi();
    renderApp('/accept-invite?token=invitation-token-value-1234567890');

    expect(await screen.findByRole('heading', { name: '비밀번호 설정' })).toBeInTheDocument();
    expect(screen.getByText('현재 다른 계정으로 로그인되어 있지만 초대 비밀번호는 설정할 수 있습니다.')).toBeInTheDocument();
  });

  it('lets an invited user set a matching password', async () => {
    let acceptedBody = '';
    mockApi((url, init) => {
      if (url.pathname === '/api/auth/me') return json({ detail: '로그인이 필요합니다.' }, 401);
      if (url.pathname === '/api/auth/invitations/accept' && init?.method === 'POST') {
        acceptedBody = String(init.body);
        return new Response(null, { status: 204 });
      }
      return undefined;
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const user = userEvent.setup();
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/accept-invite?token=invitation-token-value-1234567890']}><App /></MemoryRouter></QueryClientProvider>);

    await user.type(await screen.findByLabelText('비밀번호'), 'a-secure-password');
    await user.type(screen.getByLabelText('비밀번호 확인'), 'a-secure-password');
    await user.click(screen.getByRole('button', { name: '비밀번호 설정' }));

    expect(await screen.findByRole('heading', { name: '비밀번호 설정 완료' })).toBeInTheDocument();
    expect(JSON.parse(acceptedBody)).toEqual({ token: 'invitation-token-value-1234567890', password: 'a-secure-password' });
  });
});

describe('project administration and assignment', () => {
  it('returns to login when the session cannot be verified', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));
    renderApp('/projects', 'ADMIN', false, true);
    expect(await screen.findByRole('heading', { name: 'TOY SAST 로그인' })).toBeInTheDocument();
    expect(screen.queryByText('Failed to fetch')).not.toBeInTheDocument();
  });

  it('shows project administration to admins and assigned projects to users', async () => {
    mockApi();
    renderApp('/projects');
    expect(await screen.findByText('결제 API')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /프로젝트 등록/ })).toBeInTheDocument();
  });

  it('uses the server-authorized project response instead of a browser assignment flag', async () => {
    const fetchMock = mockApi((url) => url.pathname === `/api/projects/${scan.projectId}` ? json({ ...project, assignedToViewer: false }) : undefined);
    renderApp(`/projects/${scan.projectId}`, 'USER');
    expect(await screen.findByRole('heading', { name: project.name })).toBeInTheDocument();
    expect(wasRequested(fetchMock, `/api/projects/${scan.projectId}/scans`)).toBe(true);
    expect(wasRequested(fetchMock, '/api/engine')).toBe(true);
  });

  it('creates and edits projects through the form routes', async () => {
    const created = { ...project, id: 'created-project', name: '새 결제 API', latestScan: null };
    let saved = false;
    const savedBodies: unknown[] = [];
    mockApi((url, init) => {
      if (url.pathname === '/api/projects' && init?.method === 'POST') { savedBodies.push(JSON.parse(String(init.body))); return json(created); }
      if (url.pathname === '/api/projects/created-project') return json(created);
      if (url.pathname === '/api/projects/created-project/scans') return json({ items: [], total: 0, limit: 20, offset: 0 });
      if (url.pathname === `/api/projects/${scan.projectId}` && init?.method === 'PUT') { saved = true; savedBodies.push(JSON.parse(String(init.body))); return json({ ...project, name: '수정 결제 API' }); }
      return undefined;
    });
    const user = userEvent.setup();
    renderApp('/projects/new');
    await user.type(await screen.findByRole('textbox', { name: '프로젝트명' }), created.name);
    await user.type(screen.getByRole('textbox', { name: '설명' }), '새로운 결제 분석 프로젝트입니다.');
    await user.click(screen.getByRole('button', { name: '프로젝트 등록' }));
    expect(await screen.findByRole('heading', { name: created.name })).toBeInTheDocument();
    expect(savedBodies[0]).toMatchObject({ memberUserIds: [] });

    renderApp(`/projects/${scan.projectId}/edit`);
    const name = await screen.findByRole('textbox', { name: '프로젝트명' });
    await user.clear(name);
    await user.type(name, '수정 결제 API');
    await user.click(screen.getByRole('button', { name: '변경사항 저장' }));
    await waitFor(() => expect(saved).toBe(true));
    expect(savedBodies[1]).toMatchObject({ memberUserIds: [] });
  });

  it('shows an assigned inactive user so an admin can keep or remove the assignment', async () => {
    const inactiveUser = { id: 'inactive-user', email: 'inactive@example.com', role: 'USER', isActive: false, invitationPending: false, createdAt: scan.createdAt, updatedAt: scan.updatedAt };
    mockApi((url) => {
      if (url.pathname === '/api/admin/users') return json({ items: [inactiveUser] });
      if (url.pathname.endsWith('/members')) return json({ userIds: [inactiveUser.id] });
      return undefined;
    });

    renderApp(`/projects/${scan.projectId}/edit`);

    expect(await screen.findByText('일반 사용자 · 읽기 전용 · 비활성')).toBeInTheDocument();
    expect(screen.getByRole('checkbox')).toBeChecked();
  });

  it('deletes an empty project after confirmation', async () => {
    const emptyProject = { ...project, latestScan: null };
    let deleted = false;
    const fetchMock = mockApi((url, init) => {
      if (url.pathname === `/api/projects/${scan.projectId}` && init?.method === 'DELETE') {
        deleted = true;
        return new Response(null, { status: 204 });
      }
      if (url.pathname === `/api/projects/${scan.projectId}`) return json(emptyProject);
      if (url.pathname === '/api/projects' && deleted) return json({ items: [], total: 0, limit: 100, offset: 0 });
      return undefined;
    });
    const user = userEvent.setup();
    renderApp(`/projects/${scan.projectId}/edit`);

    const deleteTrigger = await screen.findByRole('button', { name: '프로젝트 삭제' });
    await user.click(deleteTrigger);
    expect(screen.getByRole('dialog', { name: '프로젝트를 삭제할까요?' })).toHaveTextContent(project.name);
    await user.click(screen.getByRole('button', { name: '취소' }));
    await waitFor(() => expect(deleteTrigger).toHaveFocus());
    await user.click(deleteTrigger);
    await user.click(screen.getByRole('button', { name: '삭제' }));

    await screen.findByRole('heading', { name: '프로젝트' });
    expect(wasRequested(fetchMock, `/api/projects/${scan.projectId}`)).toBe(true);
    expect(deleted).toBe(true);
  });

  it('confirms deletion of a project together with its analysis history', async () => {
    let deleted = false;
    mockApi((url, init) => {
      if (url.pathname === `/api/projects/${scan.projectId}` && init?.method === 'DELETE') {
        deleted = true;
        return new Response(null, { status: 204 });
      }
      return undefined;
    });
    const user = userEvent.setup();
    renderApp(`/projects/${scan.projectId}/edit`);

    expect(await screen.findByText('프로젝트와 모든 분석 이력 및 탐지 결과가 함께 삭제됩니다.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '프로젝트 삭제' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('모든 분석 이력, 탐지 결과, 파일 구조 정보');
    await user.click(screen.getByRole('button', { name: '삭제' }));
    await waitFor(() => expect(deleted).toBe(true));
  });

  it('keeps project deletion unavailable to general users', async () => {
    const fetchMock = mockApi();
    renderApp(`/projects/${scan.projectId}`, 'USER');
    expect(await screen.findByRole('heading', { name: project.name })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: '프로젝트 삭제' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
  });

  it('blocks project edit and delete routes for general users', async () => {
    const fetchMock = mockApi();
    renderApp(`/projects/${scan.projectId}/edit`, 'USER');

    expect(await screen.findByRole('heading', { name: '제한된 권한' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '프로젝트 삭제' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
  });

  it('pages scan history with the selected offset', async () => {
    const fetchMock = mockApi((url) => {
      if (url.pathname === `/api/projects/${scan.projectId}/scans`) return json({ items: [scan], total: 40, limit: 20, offset: Number(url.searchParams.get('offset') ?? 0) });
      return undefined;
    });
    const user = userEvent.setup();
    renderApp(`/projects/${scan.projectId}`);
    await screen.findByRole('link', { name: /payment-api\.zip/ });
    await user.click(screen.getByRole('button', { name: '다음' }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => new URL(String(input)).searchParams.get('offset') === '20')).toBe(true));
  });

  it('renders a project-load error instead of an editable form', async () => {
    mockApi((url) => url.pathname === `/api/projects/${scan.projectId}` ? json({ detail: 'project unavailable' }, 500) : undefined);
    renderApp(`/projects/${scan.projectId}/edit`);
    expect(await screen.findByRole('alert')).toHaveTextContent('project unavailable');
  });
});

describe('ZIP scan request', () => {
  it.each([['a.txt', 12, 'ZIP 형식의 파일만 업로드할 수 있습니다.'], ['empty.zip', 0, '비어 있는 ZIP 파일은 업로드할 수 없습니다.']])('rejects an invalid input file (%s)', async (name, size, message) => {
    mockApi();
    renderApp(`/projects/${scan.projectId}/scans/new`);
    fireEvent.change(await screen.findByLabelText('분석할 ZIP 파일'), { target: { files: [new File(['x'.repeat(size)], name, { type: 'application/zip' })] } });
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
  });

  it('rejects multiple dropped files', async () => {
    mockApi();
    renderApp(`/projects/${scan.projectId}/scans/new`);
    const target = (await screen.findByLabelText('분석할 ZIP 파일')).closest('label')!;
    fireEvent.drop(target, { dataTransfer: { files: [new File(['a'], 'one.zip'), new File(['b'], 'two.zip')] } });
    expect(await screen.findByRole('alert')).toHaveTextContent('ZIP 파일을 한 개만 등록해 주세요.');
  });

  it('accepts one dropped ZIP, submits its FormData, and navigates to the scan result', async () => {
    const newScan = { ...scan, scanId: '33333333-3333-4333-8333-333333333333', status: 'FAILED' as const, phase: 'FAILED' as const, message: 'drag scan stopped' };
    let submittedBody: BodyInit | null | undefined;
    mockApi((url, init) => {
      if (url.pathname === '/api/scans' && init?.method === 'POST') { submittedBody = init.body; return json(newScan); }
      if (url.pathname === `/api/scans/${newScan.scanId}`) return json(newScan);
      return undefined;
    });
    const user = userEvent.setup();
    renderApp(`/projects/${scan.projectId}/scans/new`);
    const input = await screen.findByLabelText('분석할 ZIP 파일');
    const target = input.closest('label')!;
    const source = new File(['zip'], 'drag-source.zip', { type: 'application/zip' });

    fireEvent.drop(target, { dataTransfer: { files: [source] } });

    expect(screen.getByText('drag-source.zip')).toBeInTheDocument();
    expect(screen.getByText(/0\.00 MiB · ZIP/)).toBeInTheDocument();
    const submit = screen.getByRole('button', { name: '분석 실행' });
    expect(submit).toBeEnabled();
    await user.click(submit);

    await waitFor(() => expect(submittedBody).toBeInstanceOf(FormData));
    expect((submittedBody as FormData).get('projectId')).toBe(scan.projectId);
    expect((submittedBody as FormData).get('source')).toBe(source);
    expect(await screen.findByText('drag scan stopped')).toBeInTheDocument();
  });

  it('submits a valid ZIP as FormData and navigates to the cached scan', async () => {
    const newScan = { ...scan, scanId: '22222222-2222-4222-8222-222222222222', status: 'FAILED' as const, phase: 'FAILED' as const, message: 'stopped' };
    let submittedBody: BodyInit | null | undefined;
    mockApi((url, init) => {
      if (url.pathname === '/api/scans' && init?.method === 'POST') { submittedBody = init.body; return json(newScan); }
      if (url.pathname === `/api/scans/${newScan.scanId}`) return json(newScan);
      return undefined;
    });
    const user = userEvent.setup();
    renderApp(`/projects/${scan.projectId}/scans/new`);
    fireEvent.change(await screen.findByLabelText('분석할 ZIP 파일'), { target: { files: [new File(['zip'], 'source.zip', { type: 'application/zip' })] } });
    await user.click(screen.getByRole('button', { name: '분석 실행' }));
    await waitFor(() => expect(submittedBody).toBeInstanceOf(FormData));
    expect((submittedBody as FormData).get('projectId')).toBe(scan.projectId);
    expect((submittedBody as FormData).get('source')).toBeInstanceOf(File);
    expect(await screen.findByText('stopped')).toBeInTheDocument();
  });

  it('shows engine errors without hiding the upload input', async () => {
    mockApi((url) => url.pathname === '/api/engine' ? json({ detail: 'engine unavailable' }, 503) : undefined);
    renderApp(`/projects/${scan.projectId}/scans/new`);
    expect(await screen.findByRole('alert')).toHaveTextContent('engine unavailable');
    expect(screen.getByLabelText('분석할 ZIP 파일')).toBeInTheDocument();
  });
});

describe('scan readiness and issues', () => {
  it('keeps pending results inert and does not call issue endpoints', async () => {
    const fetchMock = mockApi((url) => url.pathname === `/api/scans/${scan.scanId}` ? json({ ...scan, status: 'PENDING', phase: 'PENDING', progressPercent: null }) : undefined);
    renderApp(`/scans/${scan.scanId}`);
    expect(await screen.findByText('진행률 계산 중')).toBeInTheDocument();
    expect(document.querySelector('.scan-result-content')).toHaveAttribute('aria-hidden', 'true');
    expect(wasRequested(fetchMock, `/api/scans/${scan.scanId}/issues`)).toBe(false);
  });

  it('polls RUNNING to COMPLETED, invalidates summaries, then loads issues', async () => {
    let scanRequests = 0;
    const fetchMock = mockApi((url) => {
      if (url.pathname !== `/api/scans/${scan.scanId}`) return undefined;
      scanRequests += 1;
      return json(scanRequests === 1 ? { ...scan, status: 'RUNNING', phase: 'ANALYZING', progressPercent: 50 } : scan);
    });
    renderApp(`/scans/${scan.scanId}`);
    expect(await screen.findByText('50%')).toBeInTheDocument();
    await waitFor(() => expect(wasRequested(fetchMock, `/api/scans/${scan.scanId}/issues`)).toBe(true), { timeout: 2_500 });
    expect(await screen.findByText('탐지 이슈')).toBeInTheDocument();
  });

  it('keeps 100 percent visible until issues settle, holds for 160ms, then unmounts after the opacity transition', async () => {
    vi.useFakeTimers();
    let scanRequests = 0;
    let resolveIssues: ((response: Response) => void) | undefined;
    const issueResponse = new Promise<Response>((resolve) => { resolveIssues = resolve; });
    mockApi((url) => {
      if (url.pathname === `/api/scans/${scan.scanId}`) {
        scanRequests += 1;
        return json(scanRequests === 1 ? { ...scan, status: 'RUNNING', phase: 'ANALYZING', progressPercent: 99 } : scan);
      }
      if (url.pathname === `/api/scans/${scan.scanId}/issues`) return issueResponse as unknown as Response;
      return undefined;
    });
    renderApp(`/scans/${scan.scanId}`, 'ADMIN', true);

    await act(flushImmediateTimers);
    expect(screen.getByText('99%')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000); await Promise.resolve(); });
    await act(async () => { await flushAsyncWork(); await vi.advanceTimersByTimeAsync(1); await flushAsyncWork(); });
    expect(screen.getByText('100%')).toBeInTheDocument();
    expect(document.querySelector('.analysis-overlay')).not.toHaveClass('analysis-overlay-complete');

    await act(async () => { resolveIssues?.(json(issues)); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(159); });
    expect(document.querySelector('.analysis-overlay')).not.toHaveClass('analysis-overlay-complete');
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    const overlay = document.querySelector('.analysis-overlay');
    expect(overlay).toHaveClass('analysis-overlay-complete');
    fireEvent.transitionEnd(overlay!, { propertyName: 'opacity' });
    expect(document.querySelector('.analysis-overlay')).not.toBeInTheDocument();
  });

  it('uses the 220ms fallback when the overlay opacity transition does not end', async () => {
    vi.useFakeTimers();
    let scanRequests = 0;
    mockApi((url) => {
      if (url.pathname === `/api/scans/${scan.scanId}`) {
        scanRequests += 1;
        return json(scanRequests === 1 ? { ...scan, status: 'RUNNING', phase: 'ANALYZING', progressPercent: 99 } : scan);
      }
      return undefined;
    });
    renderApp(`/scans/${scan.scanId}`, 'ADMIN', true);

    await act(flushImmediateTimers);
    expect(screen.getByText('99%')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1); await Promise.resolve(); });
    expect(screen.getByText('탐지 이슈')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(160); });
    expect(document.querySelector('.analysis-overlay')).toHaveClass('analysis-overlay-complete');
    await act(async () => { await vi.advanceTimersByTimeAsync(219); });
    expect(document.querySelector('.analysis-overlay')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(document.querySelector('.analysis-overlay')).not.toBeInTheDocument();
  });

  it('skips the completion hold when reduced motion is preferred', async () => {
    vi.useFakeTimers();
    const originalMatchMedia = window.matchMedia;
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockImplementation((query: string) => ({ matches: query === '(prefers-reduced-motion: reduce)', addEventListener: vi.fn(), removeEventListener: vi.fn() })),
    });
    try {
      let scanRequests = 0;
      mockApi((url) => {
        if (url.pathname === `/api/scans/${scan.scanId}`) {
          scanRequests += 1;
          return json(scanRequests === 1 ? { ...scan, status: 'RUNNING', phase: 'ANALYZING', progressPercent: 99 } : scan);
        }
        return undefined;
      });
      renderApp(`/scans/${scan.scanId}`, 'ADMIN', true);

      await act(flushImmediateTimers);
      expect(screen.getByText('99%')).toBeInTheDocument();
      await act(async () => { await vi.advanceTimersByTimeAsync(1_000); await Promise.resolve(); });
      await act(async () => { await vi.advanceTimersByTimeAsync(1); await Promise.resolve(); });
      expect(screen.getByText('탐지 이슈')).toBeInTheDocument();
      await act(async () => { await vi.advanceTimersByTimeAsync(1); });
      expect(document.querySelector('.analysis-overlay')).toHaveClass('analysis-overlay-complete');
    } finally {
      Object.defineProperty(window, 'matchMedia', { configurable: true, value: originalMatchMedia });
    }
  });

  it('has no overlay for a direct completed scan', async () => {
    mockApi();
    renderApp(`/scans/${scan.scanId}`);
    expect(await screen.findByText('탐지 이슈')).toBeInTheDocument();
    expect(document.querySelector('.analysis-overlay')).not.toBeInTheDocument();
  });

  it('shows a partial parsing warning while keeping completed results available', async () => {
    const warningMessage = '분석이 완료되었습니다. 일부 파일을 완전히 해석하지 못했습니다(2개). 해당 파일의 탐지 결과는 일부 누락될 수 있습니다: src/broken.py · legacy/nashorn.js';
    mockApi((url) => url.pathname === `/api/scans/${scan.scanId}` ? json({ ...scan, message: warningMessage }) : undefined);
    renderApp(`/scans/${scan.scanId}`);

    expect(await screen.findByText(warningMessage)).toHaveClass('analysis-warning-notice');
    expect(await screen.findByText('탐지 이슈')).toBeInTheDocument();
    expect(document.querySelector('.analysis-overlay')).not.toBeInTheDocument();
  });

  it('removes the busy overlay immediately for a failed scan', async () => {
    mockApi((url) => url.pathname === `/api/scans/${scan.scanId}` ? json({ ...scan, status: 'FAILED', phase: 'FAILED', progressPercent: null, message: 'failed' }) : undefined);
    renderApp(`/scans/${scan.scanId}`);
    expect(await screen.findByText('failed')).toBeInTheDocument();
    expect(document.querySelector('.analysis-overlay')).not.toBeInTheDocument();
    expect(document.querySelector('.scan-result-content')).not.toHaveAttribute('aria-hidden');
  });

  it.each(['/issues/issue-a', '/coverage'])('does not call protected direct endpoint while scan is active (%s)', async (suffix) => {
    const fetchMock = mockApi((url) => url.pathname === `/api/scans/${scan.scanId}` ? json({ ...scan, status: 'RUNNING', phase: 'ANALYZING', progressPercent: 20 }) : undefined);
    renderApp(`/scans/${scan.scanId}${suffix}`);
    expect(await screen.findByText('분석 준비 중')).toBeInTheDocument();
    expect(wasRequested(fetchMock, `/api/scans/${scan.scanId}${suffix}`)).toBe(false);
  });

  it('uses filters and a reset cursor without calling legacy results', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    renderApp(`/scans/${scan.scanId}`);
    await screen.findByText('탐지 이슈');
    await user.click(screen.getByRole('button', { name: '다음' }));
    await user.selectOptions(screen.getByRole('combobox', { name: '위험도 필터' }), 'ERROR');
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => { const url = new URL(String(input)); return url.pathname.endsWith('/issues') && url.searchParams.get('severity') === 'ERROR' && !url.searchParams.has('cursor'); })).toBe(true));
    expect(fetchMock.mock.calls.every(([input]) => !String(input).includes('/results'))).toBe(true);
  });

  it('applies only complete canonical weakness IDs and clears the applied filter', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    renderApp(`/scans/${scan.scanId}`);
    await screen.findByText('탐지 이슈');
    const input = screen.getByRole('textbox', { name: '기준 ID (예: KISA-2021-05)' });
    const issueRequests = () => fetchMock.mock.calls
      .map(([request]) => new URL(String(request)))
      .filter((url) => url.pathname === `/api/scans/${scan.scanId}/issues`);
    const initialRequestCount = issueRequests().length;

    await user.type(input, 'KISA-2021-0');
    expect(await screen.findByText('기준 ID를 끝까지 입력하면 필터가 적용됩니다.')).toBeInTheDocument();
    expect(issueRequests()).toHaveLength(initialRequestCount);

    await user.type(input, '5');
    await waitFor(() => expect(issueRequests().at(-1)?.searchParams.get('weaknessId')).toBe('KISA-2021-05'));
    const appliedRequestCount = issueRequests().length;

    await user.type(input, '0');
    expect(await screen.findByText('KISA-2021-01~49 형식만 사용할 수 있습니다. 현재 KISA-2021-05 필터가 유지됩니다.')).toBeInTheDocument();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(issueRequests()).toHaveLength(appliedRequestCount);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    await user.clear(input);
    await waitFor(() => expect(issueRequests()).toHaveLength(appliedRequestCount + 1));
    expect(issueRequests().at(-1)?.searchParams.has('weaknessId')).toBe(false);
    expect(input).not.toHaveAttribute('aria-invalid');
  });

  it('renders issue results as a semantic list of native detail links with mobile-safe context', async () => {
    mockApi();
    renderApp(`/scans/${scan.scanId}`);

    expect(await screen.findByRole('list', { name: '분석 이슈 목록' })).toBeInTheDocument();
    const issueLink = screen.getByRole('link', { name: /기준.*SW 개발보안 가이드 · 05번.*이슈.*운영체제 명령어 삽입.*위치.*src\/App\.java:22.*판정.*탐지됨.*위험도.*높음.*신뢰도.*중간/ });
    expect(issueLink).toHaveAttribute('href', `/scans/${scan.scanId}/issues/issue-a`);
    expect(screen.getByRole('link', { name: /메모리 버퍼 오버플로우.*검토 필요.*위험도.*중간.*신뢰도.*낮음/ })).toBeInTheDocument();
    expect(screen.getByText('이전 결과 모델의 검토 신호가 포함되어 있습니다. 현재 기준으로 다시 분석해 주세요.')).toBeInTheDocument();
    expect(screen.getByText('매우 높음 0 · 높음 1 · 중간 0 · 낮음 0')).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: '분석 이슈 목록' })).not.toBeInTheDocument();
  });

  it('adds the selected directory path and scope and renders only descendant issues', async () => {
    const fetchMock = mockApi((url) => url.pathname.endsWith('/issues') && url.searchParams.get('pathScope') === 'DIRECTORY'
      ? json({ ...issues, total: 1, nextCursor: null, items: [issues.items[0]] })
      : undefined);
    const user = userEvent.setup();
    renderApp(`/scans/${scan.scanId}`);
    const directory = await screen.findByRole('treeitem', { name: /src/ });
    await user.click(directory);

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => {
      const url = new URL(String(input));
      return url.pathname.endsWith('/issues')
        && url.searchParams.get('path') === 'src'
        && url.searchParams.get('pathScope') === 'DIRECTORY'
        && !url.searchParams.has('cursor');
    })).toBe(true));
    expect(await screen.findByRole('link', { name: /운영체제 명령어 삽입/ })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /메모리 버퍼 오버플로우/ })).not.toBeInTheDocument();
    expect(screen.getAllByRole('status').some((status) => status.textContent?.includes('폴더 전체src · 이슈 1건'))).toBe(true);
  });

  it('selects the actual ZIP name as an unfiltered whole-archive view', async () => {
    const fetchMock = mockApi();
    const user = userEvent.setup();
    renderApp(`/scans/${scan.scanId}`);
    await user.click(await screen.findByRole('treeitem', { name: new RegExp(scan.archiveName) }));

    await waitFor(() => {
      const issueCalls = fetchMock.mock.calls
        .map(([input]) => new URL(String(input)))
        .filter((url) => url.pathname.endsWith('/issues'));
      expect(issueCalls.length).toBeGreaterThan(0);
      expect(issueCalls.at(-1)?.searchParams.has('path')).toBe(false);
      expect(issueCalls.at(-1)?.searchParams.has('pathScope')).toBe(false);
    });
    expect(screen.getAllByRole('status').some((status) => status.textContent?.includes(`전체${scan.archiveName} · 이슈 2건`))).toBe(true);
  });

  it('returns focus to the mobile file-tree trigger after a selection', async () => {
    const originalMatchMedia = window.matchMedia;
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockImplementation(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })),
    });
    try {
      mockApi();
      const user = userEvent.setup();
      renderApp(`/scans/${scan.scanId}`);
      const trigger = await screen.findByRole('button', { name: /파일 구조/ });
      await user.click(trigger);
      await user.click(await screen.findByRole('treeitem', { name: /src/ }));

      await waitFor(() => expect(trigger).toHaveFocus());
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
    } finally {
      Object.defineProperty(window, 'matchMedia', { configurable: true, value: originalMatchMedia });
    }
  });

  it('renders issue errors and immutable detail data', async () => {
    mockApi((url) => url.pathname.endsWith('/issues') ? json({ detail: 'issue query failed' }, 500) : undefined);
    renderApp(`/scans/${scan.scanId}`);
    expect(await screen.findByRole('alert')).toHaveTextContent('issue query failed');
    expect(document.querySelector('.scan-results-column > .skeleton-block')).not.toBeInTheDocument();
  });

  it('renders stable identifiers and KISA metadata on a successful issue detail route', async () => {
    mockApi();
    renderApp(`/scans/${scan.scanId}/issues/${detail.issueId}`);

    expect(await screen.findByRole('heading', { name: detail.weakness.name })).toBeInTheDocument();
    expect(screen.getByText('파일 경로').nextElementSibling).toHaveTextContent(detail.location.path);
    expect(screen.getByText('위험도').nextElementSibling).toHaveTextContent('높음');
    expect(screen.getByText('신뢰도').nextElementSibling).toHaveTextContent('중간');
    expect(screen.getByRole('heading', { name: '보안약점 설명' }).nextElementSibling).toHaveTextContent(detail.weakness.description!);
    expect(screen.getByText('원본 소스: 미보관')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '탐지 이유' }).nextElementSibling).toHaveTextContent(detail.detectionRationale);
    expect(screen.getByRole('heading', { name: '추가 확인사항' }).nextElementSibling).toHaveTextContent(detail.automationLimitation);
    expect(screen.queryByRole('heading', { name: '수동 검증 항목' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('heading', { name: '수정 방법' }).at(-1)?.nextElementSibling).toHaveTextContent(detail.remediation);
    expect(screen.getByRole('heading', { name: '안전한 구현 예시' }).nextElementSibling).toHaveTextContent('원본 코드 아님');
    const reference = screen.getByRole('link', { name: detail.references[0] });
    expect(reference).toHaveAttribute('href', detail.references[0]);
    expect(reference).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });

  it('uses the rule description as the detection reason without repeating the detection message', async () => {
    const described = { ...detail, rule: { ...detail.rule, description: '외부 입력이 명령 실행 함수에 도달하는 호출 구조를 탐지합니다.' } };
    mockApi((url) => url.pathname.endsWith('/issues/issue-a') ? json(described) : undefined);
    renderApp(`/scans/${scan.scanId}/issues/${detail.issueId}`);

    expect((await screen.findByRole('heading', { name: '탐지 이유' })).nextElementSibling).toHaveTextContent(described.rule.description);
    expect(screen.getAllByText(detail.rule.message)).toHaveLength(1);
    expect(screen.queryByText(detail.detectionRationale)).not.toBeInTheDocument();
  });

  it('describes a review signal as unconfirmed while retaining severity and confidence', async () => {
    const reviewDetail: IssueDetail = {
      ...detail,
      issueId: 'issue-b',
      resultStatus: 'REVIEW_REQUIRED',
      findingKind: 'REVIEW_SIGNAL',
      confidence: 'LOW',
      detectionRationale: '자동 확정이 불가능한 메모리 사용 패턴이 있어 수동 검토가 필요합니다.',
      rule: { ...detail.rule, severity: 'WARNING' },
    };
    mockApi((url) => url.pathname.endsWith('/issues/issue-b') ? json(reviewDetail) : undefined);
    renderApp(`/scans/${scan.scanId}/issues/issue-b`);

    expect((await screen.findAllByText('검토 필요')).length).toBeGreaterThan(0);
    expect(screen.queryByText('탐지됨')).not.toBeInTheDocument();
    expect(screen.getByText('이전 결과 모델의 검토 신호입니다. 확정 탐지로 해석하지 말고 현재 기준으로 다시 분석해 주세요.')).toBeInTheDocument();
    expect(screen.getByText('위험도').nextElementSibling).toHaveTextContent('중간');
    expect(screen.getByText('신뢰도').nextElementSibling).toHaveTextContent('낮음');
  });
});

describe('assignment, coverage, and no-scan states', () => {
  it.each(['/issues/issue-a', '/coverage'])('lets the API authorize general-user result requests (%s)', async (suffix) => {
    const fetchMock = mockApi();
    renderApp(`/scans/${scan.scanId}${suffix}`, 'USER');
    if (suffix === '/coverage') expect(await screen.findByRole('heading', { name: '검사 기준 리스트' })).toBeInTheDocument();
    else expect(await screen.findByRole('heading', { name: detail.weakness.name })).toBeInTheDocument();
    expect(wasRequested(fetchMock, `/api/scans/${scan.scanId}${suffix}`)).toBe(true);
  });

  it('routes legacy issue data to the 49-criterion coverage page', async () => {
    mockApi((url) => url.pathname.endsWith('/issues') ? json({ scanId: scan.scanId, issueModelAvailable: false, unavailableReason: 'LEGACY_SCAN', items: [], total: 0, limit: 50, nextCursor: null, stats: null }) : undefined);
    renderApp(`/scans/${scan.scanId}`);
    expect(await screen.findByRole('heading', { name: '검사 기준 리스트' })).toBeInTheDocument();
    expect(screen.getByText('총 49개 보안약점')).toBeInTheDocument();
  });

  it('keeps contextual labels in each responsive coverage row', async () => {
    mockApi();
    renderApp(`/scans/${scan.scanId}/coverage`);

    const table = await screen.findByRole('table', { name: '검사 기준 리스트, 총 49개 보안약점' });
    const dataRow = table.querySelectorAll('[role="row"]')[1];
    expect(dataRow).toHaveTextContent('번호');
    expect(dataRow).toHaveTextContent('검사 기준');
    expect(dataRow).toHaveTextContent('언어별 자동 탐지 결과');
    expect(dataRow).toHaveTextContent('이슈');
  });

  it('hides routine coverage reasons while keeping detected counts', async () => {
    mockApi((url) => url.pathname.endsWith('/coverage') ? json({ ...demoCoverage, scanId: scan.scanId }) : undefined);
    renderApp(`/scans/${scan.scanId}/coverage`);

    const table = await screen.findByRole('table', { name: '검사 기준 리스트, 총 49개 보안약점' });
    expect(table).not.toHaveTextContent('해당 기준과 언어에 검증된 자동 탐지 룰이 없습니다.');
    expect(table).not.toHaveTextContent('검증된 자동 탐지 룰을 실행했지만 일치 항목이 없습니다.');
    expect(table).toHaveTextContent('1건');
  });

  it('labels a terminal scan without a snapshot as legacy', async () => {
    mockApi((url) => url.pathname === `/api/projects/${scan.projectId}` ? json({ ...project, latestScan: { ...scan, engineSnapshot: null } }) : undefined);
    renderApp(`/projects/${scan.projectId}`);
    expect(await screen.findByText('기록 없음 · 레거시 분석')).toBeInTheDocument();
    expect(screen.getByText('완료 당시 엔진 스냅샷 없음')).toBeInTheDocument();
  });

  it('uses live engine metadata and retains the empty workspace when no scan exists', async () => {
    mockApi((url) => {
      if (url.pathname === `/api/projects/${scan.projectId}`) return json({ ...project, latestScan: null });
      if (url.pathname === `/api/projects/${scan.projectId}/scans`) return json({ items: [], total: 0, limit: 20, offset: 0 });
      return undefined;
    });
    renderApp(`/projects/${scan.projectId}`);
    expect(await screen.findByText('Semgrep 1.174.0')).toBeInTheDocument();
    expect(screen.getByText('분석 이력이 없습니다.')).toBeInTheDocument();
  });
});
