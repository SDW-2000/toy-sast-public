export type Role = 'ADMIN' | 'USER';

export type UserSummary = {
  id: string;
  email: string;
  role: Role;
  isActive: boolean;
  invitationPending: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AuthenticatedUser = UserSummary & {
  sessionExpiresAt: string;
};

export type UserList = {
  items: UserSummary[];
};

export type ProjectMemberList = {
  userIds: string[];
};

export type EngineSnapshot = {
  engineName: string;
  engineVersion: string;
  rulepackName: string;
  rulepackVersion: string;
  rulesetDigest: string;
  registeredRuleCount: number;
  executedRuleCount: number | null;
};

export type Project = {
  id: string;
  name: string;
  description: string;
  assignedToViewer: boolean;
  createdAt: string;
  updatedAt: string;
  latestScan: ScanSummary | null;
};

export type ProjectList = {
  items: Project[];
  total: number;
  limit: number;
  offset: number;
};

export type ScanList = {
  items: ScanSummary[];
  total: number;
  limit: number;
  offset: number;
};

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type ScanPhase =
  | 'PENDING'
  | 'ZIP_VALIDATION'
  | 'LANGUAGE_DETECTION'
  | 'ANALYZING'
  | 'NORMALIZING'
  | 'COMPLETED'
  | 'FAILED';

export type ScanSummary = {
  scanId: string;
  projectId: string;
  archiveName: string;
  status: ScanStatus;
  phase: ScanPhase;
  progressPercent: number | null;
  completedUnits: number;
  totalUnits: number | null;
  archiveFileCount: number | null;
  analysisFileCount: number | null;
  detectedLanguages: string[];
  languageFileCounts: Record<string, number>;
  engineSnapshot: EngineSnapshot | null;
  createdAt: string;
  updatedAt: string;
};

export type ScanProgress = ScanSummary & {
  message: string;
  errorCode?: string | null;
};

export type Finding = {
  ruleId: string;
  kind: FindingKind | null;
  language: string;
  path: string;
  startLine: number;
  message: string;
  severity: string;
};

export type ImplementationStatus =
  | 'IMPLEMENTED'
  | 'PARTIALLY_IMPLEMENTED'
  | 'MANUAL_REVIEW_REQUIRED'
  | 'NOT_IMPLEMENTED';

export type SupportStatus =
  | 'SUPPORTED'
  | 'NOT_SUPPORTED'
  /** @deprecated v1 response compatibility only. */
  | 'PARTIALLY_SUPPORTED'
  /** @deprecated v1 response compatibility only. */
  | 'MANUAL_REVIEW_REQUIRED';

export type ResultStatus =
  | 'DETECTED'
  | 'NOT_DETECTED'
  | 'NOT_SUPPORTED'
  | 'CHECK_FAILED'
  /** @deprecated v1 response compatibility only. */
  | 'REVIEW_REQUIRED';

export type WeaknessResult = {
  weaknessId: string;
  number: number;
  category: string;
  categoryNumber: number;
  name: string;
  description: string | null;
  sastClassification: string;
  implementationStatus: ImplementationStatus | null;
  supportStatus: SupportStatus;
  resultStatus: ResultStatus;
  reason: string;
  findingCount: number;
  findings: Finding[];
  languages?: CoverageLanguageResult[];
};

export type ScanResults = {
  scanId: string;
  status: ScanStatus;
  detectedLanguages: string[];
  supportedRuleCount: number | null;
  rulepackVersion: string | null;
  totalWeaknessCount: number;
  results: WeaknessResult[];
};

export type FileManifestEntryType = 'DIRECTORY' | 'FILE';

export type FileAnalysisState =
  | 'DIRECTORY'
  | 'TARGET'
  | 'EXCLUDED_DIRECTORY'
  | 'UNSUPPORTED_EXTENSION';

export type FileManifestNode = {
  path: string;
  parentPath: string | null;
  name: string;
  depth: number;
  entryType: FileManifestEntryType;
  sizeBytes: number | null;
  language: string | null;
  analysisState: FileAnalysisState;
  findingCount: number;
  hasChildren: boolean;
};

export type FileManifestPage = {
  scanId: string;
  manifestAvailable: boolean;
  manifestVersion: 1 | null;
  unavailableReason: 'LEGACY_SCAN' | null;
  parentPath: string | null;
  items: FileManifestNode[];
  nextCursor: string | null;
};

export type FileSelection = {
  path: string;
  pathScope: 'FILE' | 'DIRECTORY';
} | {
  path: '';
  pathScope: 'ARCHIVE';
  archiveName: string;
};

export type IssueResultStatus = 'DETECTED' | 'REVIEW_REQUIRED';
export type IssueSeverity = 'ERROR' | 'WARNING' | 'INFO';
export type IssueConfidence = 'MEDIUM' | 'LOW';
export type FindingKind = 'DETECTED' | 'REVIEW_SIGNAL';
export type IssuePathScope = FileSelection['pathScope'];

export type IssueListFilters = {
  status?: IssueResultStatus;
  severity?: IssueSeverity;
  language?: string;
  weaknessId?: string;
  path?: string;
  pathScope?: IssuePathScope;
  limit?: number;
  cursor?: string;
};

export type IssueListItem = {
  issueId: string;
  fingerprint: string;
  fingerprintVersion: 1;
  detectionBasisVersion: 1;
  resultStatus: IssueResultStatus;
  findingKind: FindingKind;
  severity: IssueSeverity;
  confidence: IssueConfidence;
  detectionRationale: string;
  weaknessId: string;
  weaknessNumber: number;
  weaknessName: string;
  implementationStatus: ImplementationStatus;
  ruleId: string;
  language: string;
  path: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  message: string;
};

export type IssueSeverityCounts = {
  ERROR: number;
  WARNING: number;
  INFO: number;
};

export type IssueStats = {
  totalIssueCount: number;
  detectedIssueCount: number;
  /** @deprecated v1 response compatibility only. */
  reviewSignalCount?: number;
  severityCounts: IssueSeverityCounts;
};

type IssueListBase = {
  scanId: string;
  items: IssueListItem[];
  total: number;
  limit: number;
  nextCursor: string | null;
};

export type AvailableIssueList = IssueListBase & {
  issueModelAvailable: true;
  unavailableReason: null;
  stats: IssueStats;
};

export type LegacyIssueList = IssueListBase & {
  issueModelAvailable: false;
  unavailableReason: 'LEGACY_SCAN';
  items: [];
  total: 0;
  nextCursor: null;
  stats: null;
};

export type IssueList = AvailableIssueList | LegacyIssueList;

export type IssueDetail = {
  scanId: string;
  issueId: string;
  fingerprint: string;
  fingerprintVersion: 1;
  detectionBasisVersion: 1;
  resultStatus: IssueResultStatus;
  findingKind: FindingKind;
  confidence: IssueConfidence;
  detectionRationale: string;
  weakness: {
    weaknessId: string;
    number: number;
    category: string;
    categoryNumber: number;
    name: string;
    description: string;
    sastClassification: string;
    implementationStatus: ImplementationStatus;
  };
  rule: {
    ruleId: string;
    language: string;
    severity: IssueSeverity;
    message: string;
    description: string | null;
    cweId: string | null;
  };
  location: {
    path: string;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
  };
  engineSnapshot: EngineSnapshot;
  evidence: {
    available: false;
    reason: 'SOURCE_NOT_RETAINED';
  };
  automationLimitation: string;
  manualVerificationChecks?: string[];
  remediation: string;
  safeImplementationExample: string;
  references: string[];
};

export type CoverageItem = {
  weaknessId: string;
  number: number;
  category: string;
  categoryNumber: number;
  name: string;
  description: string | null;
  sastClassification: string;
  implementationStatus?: ImplementationStatus | null;
  /** Legacy v1 flat fields. v2 uses languages for every detected language. */
  supportStatus?: SupportStatus;
  resultStatus?: ResultStatus;
  reason: string;
  findingCount: number;
  languages?: CoverageLanguageResult[];
};

export type CoverageLanguageResult = {
  language: string;
  supportStatus: SupportStatus;
  resultStatus: ResultStatus;
  executedRuleCount: number;
  findingCount: number;
  reason: string;
};

export type ScanCoverage = {
  scanId: string;
  coverageModelVersion: 1 | 2 | null;
  totalWeaknessCount: 49;
  summary: {
    totalCriterionCount: 49;
    detectedCriterionCount: number;
    reviewRequiredCriterionCount?: number;
    notDetectedCriterionCount: number;
    notSupportedCriterionCount: number;
    checkFailedCriterionCount?: number;
    totalLanguageResultCount?: number;
    totalFindingCount: number;
    issueStats: IssueStats | null;
  };
  items: CoverageItem[];
  legacyNotice?: string | null;
};
