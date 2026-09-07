import type { LegacyIssueList, ScanCoverage, ScanProgress, ScanResults, WeaknessResult } from './domain';

const weaknessNames = [
  'SQL 삽입', '코드 삽입', '경로 조작 및 자원 삽입', '크로스사이트 스크립트',
  '운영체제 명령어 삽입', '위험한 형식 파일 업로드', '신뢰되지 않는 URL 주소로 자동접속 연결',
  '부적절한 XML 외부 개체 참조', 'XML 삽입', 'LDAP 삽입', '크로스사이트 요청 위조',
  '서버사이드 요청 위조', 'HTTP 응답분할', '정수형 오버플로우',
  '보안기능 결정에 사용되는 부적절한 입력값', '메모리 버퍼 오버플로우', '포맷 스트링 삽입',
  '적절한 인증 없는 중요 기능 허용', '부적절한 인가', '중요한 자원에 대한 잘못된 권한 설정',
  '취약한 암호화 알고리즘 사용', '암호화되지 않은 중요정보', '하드코드된 중요정보',
  '충분하지 않은 키 길이 사용', '적절하지 않은 난수 값 사용', '취약한 비밀번호 허용',
  '부적절한 전자서명 확인', '부적절한 인증서 유효성 검증',
  '사용자 하드디스크에 저장되는 쿠키를 통한 정보노출', '주석문 안에 포함된 시스템 주요정보',
  '솔트 없이 일방향 해쉬 함수 사용', '무결성 검사 없는 코드 다운로드', '반복된 인증시도 제한 기능 부재',
  '경쟁조건 : 검사 시점과 사용 시점(TOCTOU)', '종료되지 않는 반복문 또는 재귀함수',
  '오류 메시지 정보노출', '오류상황 대응 부재', '부적절한 예외 처리', 'Null Pointer 역참조',
  '부적절한 자원 해제', '해제된 자원 사용', '초기화되지 않은 변수 사용',
  '신뢰할 수 없는 데이터의 역직렬화', '잘못된 세션에 의한 데이터 정보노출',
  '제거되지 않고 남은 디버그 코드', 'Public 메서드부터 반환된 Private 배열',
  'Private 배열에 Public 데이터 할당', 'DNS lookup에 의존한 보안결정', '취약한 API 사용',
];

const categories = [
  ['입력데이터 검증 및 표현', 17], ['보안기능', 16], ['시간 및 상태', 2],
  ['에러처리', 3], ['코드오류', 5], ['캡슐화', 4], ['API 오용', 2],
] as const;

const autoWeaknesses = new Set([2, 5, 21, 23, 24, 25, 30, 31, 45, 46, 47, 49]);
const javaOnlyDemoWeaknesses = new Set([46, 47, 49]);
function buildDemoResults(): WeaknessResult[] {
  let categoryIndex = 0;
  let categoryStart = 0;
  return weaknessNames.map((name, index) => {
    while (index >= categoryStart + categories[categoryIndex][1]) {
      categoryStart += categories[categoryIndex][1];
      categoryIndex += 1;
    }
    const number = index + 1;
    const detected = number === 2 || number === 5;
    const findings = number === 2
      ? [
          {
            ruleId: 'kisa-2021-02-javascript-code-injection', language: 'JavaScript',
            kind: 'DETECTED' as const,
            path: 'web/src/legacy-evaluator.js', startLine: 17,
            message: '외부 입력이 eval 호출로 흐릅니다.', severity: 'ERROR',
          },
          {
            ruleId: 'kisa-2021-02-python-code-injection', language: 'Python',
            kind: 'DETECTED' as const,
            path: 'worker/legacy_evaluator.py', startLine: 11,
            message: '외부 입력이 eval 호출로 흐릅니다.', severity: 'ERROR',
          },
        ]
      : number === 5
        ? [{
            ruleId: 'kisa-2021-05-java-os-command-injection', language: 'Java',
            kind: 'DETECTED' as const,
            path: 'src/main/java/PaymentRunner.java', startLine: 48,
            message: '외부 입력이 Runtime.exec 호출로 흐릅니다.', severity: 'ERROR',
          }]
        : [];
    const isSupported = autoWeaknesses.has(number);
    const languages = demoScanLanguages.map((language) => {
      const languageFindingCount = findings.filter((finding) => finding.language === language).length;
      const languageSupported = isSupported && (!javaOnlyDemoWeaknesses.has(number) || language === 'Java');
      return {
        language,
        supportStatus: languageSupported ? 'SUPPORTED' as const : 'NOT_SUPPORTED' as const,
        resultStatus: !languageSupported ? 'NOT_SUPPORTED' as const : languageFindingCount > 0 ? 'DETECTED' as const : 'NOT_DETECTED' as const,
        executedRuleCount: languageSupported ? 1 : 0,
        findingCount: languageFindingCount,
        reason: !languageSupported
          ? '해당 기준과 언어에 검증된 자동 탐지 룰이 없습니다.'
          : languageFindingCount > 0
            ? '검증된 자동 탐지 룰이 코드 위치와 일치했습니다.'
            : '검증된 자동 탐지 룰을 실행했지만 일치 항목이 없습니다.',
      };
    });
    return {
      weaknessId: `KISA-2021-${String(number).padStart(2, '0')}`,
      number,
      category: categories[categoryIndex][0],
      categoryNumber: index - categoryStart + 1,
      name,
      description: `SW 개발보안 가이드 ${number}번 ${name} 기준입니다.`,
      sastClassification: isSupported ? 'AUTO' : 'UNSUPPORTED',
      implementationStatus: isSupported ? 'PARTIALLY_IMPLEMENTED' : 'NOT_IMPLEMENTED',
      supportStatus: isSupported ? 'SUPPORTED' : 'NOT_SUPPORTED',
      resultStatus: detected ? 'DETECTED' : isSupported ? 'NOT_DETECTED' : 'NOT_SUPPORTED',
      reason: detected
        ? '검증된 SAST 규칙의 제한된 범위에서 취약 패턴을 발견했습니다.'
        : isSupported
          ? '검증된 자동 탐지 룰을 실행했지만 일치 항목이 없습니다.'
          : '해당 기준과 언어에 검증된 자동 탐지 룰이 없습니다.',
      findingCount: findings.length,
      findings,
      languages,
    };
  });
}

const demoScanLanguages = ['Java', 'JavaScript', 'Python'] as const;

export const demoScan: ScanProgress = {
  scanId: 'demo-scan-001', projectId: 'payment-api', status: 'COMPLETED', phase: 'COMPLETED',
  archiveName: 'toy-sast-demo.zip', progressPercent: 100, completedUnits: 79,
  totalUnits: 79, archiveFileCount: 12,
  analysisFileCount: 12, detectedLanguages: ['Java', 'JavaScript', 'Python'],
  languageFileCounts: { Java: 4, JavaScript: 4, Python: 4 },
  engineSnapshot: {
    engineName: 'Semgrep', engineVersion: '1.174.0', rulepackName: 'KISA 2021',
    rulepackVersion: 'kisa-2021-v2', rulesetDigest: 'demo', registeredRuleCount: 86,
    executedRuleCount: 79,
  },
  message: '분석이 완료되었습니다.',
  createdAt: '2026-08-27T09:33:00Z', updatedAt: '2026-08-27T09:41:42Z',
};

export const demoResults: ScanResults = {
  scanId: demoScan.scanId,
  status: 'COMPLETED',
  detectedLanguages: ['Java', 'JavaScript', 'Python'],
  supportedRuleCount: 79,
  rulepackVersion: 'kisa-2021-v2',
  totalWeaknessCount: 49,
  results: buildDemoResults(),
};

export function demoIssueList(limit = 50): LegacyIssueList {
  return {
    scanId: demoScan.scanId,
    issueModelAvailable: false,
    unavailableReason: 'LEGACY_SCAN',
    items: [],
    total: 0,
    limit,
    nextCursor: null,
    stats: null,
  };
}

const demoCoverageItems = demoResults.results.map((result) => ({
  weaknessId: result.weaknessId,
  number: result.number,
  category: result.category,
  categoryNumber: result.categoryNumber,
  name: result.name,
  description: result.description,
  sastClassification: result.sastClassification,
  implementationStatus: result.implementationStatus,
  supportStatus: result.supportStatus,
  resultStatus: result.resultStatus,
  reason: result.reason,
  findingCount: result.findingCount,
  languages: result.languages,
}));

export const demoCoverage: ScanCoverage = {
  scanId: demoScan.scanId,
  coverageModelVersion: 2,
  totalWeaknessCount: 49,
  summary: {
    totalCriterionCount: 49,
    detectedCriterionCount: demoCoverageItems.filter((item) => item.resultStatus === 'DETECTED').length,
    reviewRequiredCriterionCount: 0,
    notDetectedCriterionCount: demoCoverageItems.filter((item) => item.resultStatus === 'NOT_DETECTED').length,
    notSupportedCriterionCount: demoCoverageItems.filter((item) => item.resultStatus === 'NOT_SUPPORTED').length,
    totalFindingCount: demoCoverageItems.reduce((total, item) => total + item.findingCount, 0),
    issueStats: null,
  },
  items: demoCoverageItems,
};
