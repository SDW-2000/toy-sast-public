import { demoCoverage, demoIssueList, demoScan } from './fixtures';
import type {
  AuthenticatedUser,
  EngineSnapshot,
  FileManifestPage,
  IssueDetail,
  IssueList,
  IssueListFilters,
  Project,
  ProjectList,
  ProjectMemberList,
  ScanCoverage,
  ScanList,
  ScanProgress,
  UserList,
  UserSummary,
} from './domain';

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

async function fetchResponse(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  try {
    const response = await fetch(input, { ...init, credentials: 'include' });
    const path = new URL(String(input), window.location.origin).pathname;
    if (response.status === 401 && path !== '/api/auth/me' && path !== '/api/auth/login') {
      window.dispatchEvent(new Event('toy-sast-session-expired'));
    }
    return response;
  } catch {
    throw new Error('서버에 연결하지 못했습니다. API 실행 상태와 네트워크를 확인한 뒤 다시 시도해 주세요.');
  }
}

export const authService = {
  async login(input: { email: string; password: string }): Promise<AuthenticatedUser> {
    return parseResponse<AuthenticatedUser>(await fetchResponse(`${apiBaseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }));
  },
  async logout(): Promise<void> {
    const response = await fetchResponse(`${apiBaseUrl}/api/auth/logout`, { method: 'POST' });
    if (!response.ok) await parseResponse(response);
  },
  async me(): Promise<AuthenticatedUser> {
    return parseResponse<AuthenticatedUser>(await fetchResponse(`${apiBaseUrl}/api/auth/me`));
  },
  async acceptInvitation(input: { token: string; password: string }): Promise<void> {
    const response = await fetchResponse(`${apiBaseUrl}/api/auth/invitations/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
    if (!response.ok) await parseResponse(response);
  },
};

export const adminUserService = {
  async list(): Promise<UserList> {
    return parseResponse<UserList>(await fetchResponse(`${apiBaseUrl}/api/admin/users`));
  },
  async invite(input: { email: string }): Promise<UserSummary> {
    return parseResponse<UserSummary>(await fetchResponse(`${apiBaseUrl}/api/admin/users/invitations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }));
  },
  async setActive(userId: string, isActive: boolean): Promise<UserSummary> {
    return parseResponse<UserSummary>(await fetchResponse(`${apiBaseUrl}/api/admin/users/${userId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isActive }),
    }));
  },
};

export const projectMemberService = {
  async get(projectId: string): Promise<ProjectMemberList> {
    return parseResponse<ProjectMemberList>(await fetchResponse(`${apiBaseUrl}/api/projects/${projectId}/members`));
  },
  async update(projectId: string, userIds: string[]): Promise<ProjectMemberList> {
    return parseResponse<ProjectMemberList>(await fetchResponse(`${apiBaseUrl}/api/projects/${projectId}/members`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userIds }),
    }));
  },
};

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { detail?: string | { msg?: string }[] } | null;
    const detail = Array.isArray(payload?.detail)
      ? payload.detail.map((item) => item.msg).filter(Boolean).join(', ')
      : payload?.detail;
    throw new Error(detail || '요청을 처리하지 못했습니다.');
  }
  return response.json() as Promise<T>;
}

function queryString(values: Record<string, string | number | undefined>) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== '') params.set(key, String(value));
  });
  const query = params.toString();
  return query ? `?${query}` : '';
}

export const engineService = {
  async get(): Promise<EngineSnapshot> {
    return parseResponse<EngineSnapshot>(await fetchResponse(`${apiBaseUrl}/api/engine`));
  },
};

export const projectService = {
  async list(filters: { query?: string; language?: string; limit?: number; offset?: number } = {}): Promise<ProjectList> {
    return parseResponse<ProjectList>(await fetchResponse(`${apiBaseUrl}/api/projects${queryString(filters)}`));
  },
  async get(projectId: string): Promise<Project> {
    return parseResponse<Project>(await fetchResponse(`${apiBaseUrl}/api/projects/${projectId}`));
  },
  async create(input: { name: string; description: string; assignedToViewer?: boolean; memberUserIds?: string[] }): Promise<Project> {
    return parseResponse<Project>(await fetchResponse(`${apiBaseUrl}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }));
  },
  async update(projectId: string, input: { name: string; description: string; assignedToViewer?: boolean; memberUserIds?: string[] }): Promise<Project> {
    return parseResponse<Project>(await fetchResponse(`${apiBaseUrl}/api/projects/${projectId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }));
  },
  async remove(projectId: string): Promise<void> {
    const response = await fetchResponse(`${apiBaseUrl}/api/projects/${projectId}`, { method: 'DELETE' });
    if (!response.ok) await parseResponse(response);
  },
  async scans(projectId: string, paging: { limit?: number; offset?: number } = {}): Promise<ScanList> {
    return parseResponse<ScanList>(await fetchResponse(
      `${apiBaseUrl}/api/projects/${projectId}/scans${queryString(paging)}`,
    ));
  },
};

export const scanService = {
  async create(projectId: string, source: File): Promise<ScanProgress> {
    const formData = new FormData();
    formData.append('projectId', projectId);
    formData.append('source', source);
    return parseResponse<ScanProgress>(await fetchResponse(`${apiBaseUrl}/api/scans`, {
      method: 'POST', body: formData,
    }));
  },
  async get(scanId: string): Promise<ScanProgress> {
    if (scanId === demoScan.scanId) return demoScan;
    return parseResponse<ScanProgress>(await fetchResponse(`${apiBaseUrl}/api/scans/${scanId}`));
  },
  async issues(scanId: string, filters: IssueListFilters = {}): Promise<IssueList> {
    if (scanId === demoScan.scanId) return demoIssueList(filters.limit);
    return parseResponse<IssueList>(await fetchResponse(
      `${apiBaseUrl}/api/scans/${scanId}/issues${queryString(filters)}`,
    ));
  },
  async issue(scanId: string, issueId: string): Promise<IssueDetail> {
    return parseResponse<IssueDetail>(await fetchResponse(`${apiBaseUrl}/api/scans/${scanId}/issues/${issueId}`));
  },
  async coverage(scanId: string): Promise<ScanCoverage> {
    if (scanId === demoScan.scanId) return demoCoverage;
    return parseResponse<ScanCoverage>(await fetchResponse(`${apiBaseUrl}/api/scans/${scanId}/coverage`));
  },
  async files(
    scanId: string,
    options: { parentPath?: string; limit?: number; cursor?: string } = {},
  ): Promise<FileManifestPage> {
    if (scanId === demoScan.scanId) {
      return {
        scanId,
        manifestAvailable: false,
        manifestVersion: null,
        unavailableReason: 'LEGACY_SCAN',
        parentPath: options.parentPath ?? null,
        items: [],
        nextCursor: null,
      };
    }
    return parseResponse<FileManifestPage>(await fetchResponse(
      `${apiBaseUrl}/api/scans/${scanId}/files${queryString(options)}`,
    ));
  },
};
