import { scanService } from './services';
import type { IssueDetail, IssueList, ScanCoverage } from './domain';
import { demoCoverage, demoIssueList, demoScan } from './fixtures';

describe('scanService.files', () => {
  afterEach(() => vi.restoreAllMocks());

  it('uses and preserves the exact manifest API contract', async () => {
    const payload = {
      scanId: '44444444-4444-4444-8444-444444444444',
      manifestAvailable: true,
      manifestVersion: 1,
      unavailableReason: null,
      parentPath: 'src',
      items: [{
        path: 'src/App.tsx',
        parentPath: 'src',
        name: 'App.tsx',
        depth: 2,
        entryType: 'FILE',
        sizeBytes: 7421,
        language: 'JavaScript',
        analysisState: 'TARGET',
        findingCount: 2,
        hasChildren: false,
      }],
      nextCursor: 'opaque-next-page',
    } as const;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify(payload),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));

    await expect(scanService.files(payload.scanId, {
      parentPath: 'src',
      limit: 100,
      cursor: 'opaque-current-page',
    })).resolves.toEqual(payload);
    const url = new URL(String(fetchMock.mock.calls[0][0]));
    expect(url.pathname).toBe(`/api/scans/${payload.scanId}/files`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      parentPath: 'src',
      limit: '100',
      cursor: 'opaque-current-page',
    });
  });
});

describe('scanService issue and coverage contracts', () => {
  afterEach(() => vi.restoreAllMocks());

  it('encodes every combined issue filter as the agreed camelCase query pair', async () => {
    const payload: IssueList = {
      scanId: '55555555-5555-4555-8555-555555555555',
      issueModelAvailable: true,
      unavailableReason: null,
      items: [],
      total: 0,
      limit: 100,
      nextCursor: null,
      stats: {
        totalIssueCount: 0,
        detectedIssueCount: 0,
        reviewSignalCount: 0,
        severityCounts: { ERROR: 0, WARNING: 0, INFO: 0 },
      },
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));

    await expect(scanService.issues(payload.scanId, {
      status: 'DETECTED',
      severity: 'ERROR',
      language: 'Java & Kotlin',
      weaknessId: 'KISA-2021-05',
      path: 'src/main/Payment Runner.java',
      pathScope: 'DIRECTORY',
      limit: 100,
      cursor: 'page+two',
    })).resolves.toEqual(payload);

    const url = new URL(String(fetchMock.mock.calls[0][0]));
    expect(url.pathname).toBe(`/api/scans/${payload.scanId}/issues`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      status: 'DETECTED',
      severity: 'ERROR',
      language: 'Java & Kotlin',
      weaknessId: 'KISA-2021-05',
      path: 'src/main/Payment Runner.java',
      pathScope: 'DIRECTORY',
      limit: '100',
      cursor: 'page+two',
    });
    expect(url.search).not.toContain('undefined');
  });

  it('omits undefined issue filters instead of serializing empty query pairs', async () => {
    const payload: IssueList = {
      scanId: '66666666-6666-4666-8666-666666666666',
      issueModelAvailable: false,
      unavailableReason: 'LEGACY_SCAN',
      items: [],
      total: 0,
      limit: 50,
      nextCursor: null,
      stats: null,
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));

    await scanService.issues(payload.scanId, { language: undefined, path: undefined, limit: 50 });

    const url = new URL(String(fetchMock.mock.calls[0][0]));
    expect(Object.fromEntries(url.searchParams)).toEqual({ limit: '50' });
  });

  it('preserves the exact nested issue-detail camelCase response and URL', async () => {
    const payload: IssueDetail = {
      scanId: '77777777-7777-4777-8777-777777777777',
      issueId: 'issue-123',
      fingerprint: 'a'.repeat(64),
      fingerprintVersion: 1,
      detectionBasisVersion: 1,
      resultStatus: 'DETECTED',
      findingKind: 'DETECTED',
      confidence: 'MEDIUM',
      detectionRationale: '외부 입력이 명령 실행 API에 전달되는 패턴이 일치했습니다.',
      weakness: {
        weaknessId: 'KISA-2021-05', number: 5, category: '입력데이터 검증 및 표현',
        categoryNumber: 5, name: '운영체제 명령어 삽입', description: '명령어 인젝션',
        sastClassification: 'AUTO', implementationStatus: 'PARTIALLY_IMPLEMENTED',
      },
      rule: {
        ruleId: 'kisa-2021-05-java-os-command-injection', language: 'Java', severity: 'ERROR',
        message: '외부 입력이 명령 실행으로 흐릅니다.', description: null, cweId: null,
      },
      location: { path: 'src/main/PaymentRunner.java', startLine: 48, startColumn: 3, endLine: 48, endColumn: 27 },
      engineSnapshot: {
        engineName: 'Semgrep', engineVersion: '1.174.0', rulepackName: 'KISA 2021',
        rulepackVersion: 'kisa-2021-v2', rulesetDigest: 'digest', registeredRuleCount: 86, executedRuleCount: 86,
      },
      evidence: { available: false, reason: 'SOURCE_NOT_RETAINED' },
      automationLimitation: '정적 규칙은 실제 실행 경로를 확인하지 않습니다.',
      manualVerificationChecks: ['외부 입력 도달성을 확인합니다.'],
      remediation: '허용 목록 검증과 안전한 API를 적용합니다.',
      safeImplementationExample: '개념 예시(원본 코드 아님): validator.requireAllowed(value)',
      references: ['https://cwe.mitre.org/data/index.html'],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));

    await expect(scanService.issue(payload.scanId, payload.issueId)).resolves.toEqual(payload);
    expect(new URL(String(fetchMock.mock.calls[0][0])).pathname).toBe(
      `/api/scans/${payload.scanId}/issues/${payload.issueId}`,
    );
  });

  it('uses the coverage URL and retains the explicit legacy fixture contracts', async () => {
    const payload: ScanCoverage = { ...demoCoverage, scanId: '88888888-8888-4888-8888-888888888888' };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } },
    ));

    await expect(scanService.coverage(payload.scanId)).resolves.toEqual(payload);
    expect(new URL(String(fetchMock.mock.calls[0][0])).pathname).toBe(`/api/scans/${payload.scanId}/coverage`);

    await expect(scanService.issues(demoScan.scanId)).resolves.toEqual(demoIssueList());
    await expect(scanService.coverage(demoScan.scanId)).resolves.toEqual(demoCoverage);
  });
});

describe('service error evidence', () => {
  afterEach(() => vi.restoreAllMocks());

  it.each([
    [JSON.stringify({ detail: 'scan unavailable' }), 'application/json', 'scan unavailable'],
    ['upstream gateway failed', 'text/plain', '요청을 처리하지 못했습니다.'],
  ])('keeps an explicit failure when an error body is %s', async (body, contentType, message) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(body, {
      status: 502,
      headers: { 'Content-Type': contentType },
    }));

    await expect(scanService.get('99999999-9999-4999-8999-999999999999')).rejects.toThrow(message);
  });
});
