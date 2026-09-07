import { useEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, DragEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ArrowRight, FileArchive, LockKeyhole, Plus, ScanSearch, ShieldCheck } from 'lucide-react';
import {
  AnalysisOverlay, AppShell, Button, EmptyState, ErrorPanel, Field, FileSummary,
  FilterInput, PageHeader, StatusPill, TextInput,
} from './components';
import type { AuthenticatedUser, EngineSnapshot, FileSelection, IssueDetail, IssueListFilters, IssueListItem, Project, Role, ScanCoverage, ScanProgress, ScanSummary } from './domain';
import { FileTree } from './file-tree';
import { demoScan } from './fixtures';
import { adminUserService, authService, engineService, projectMemberService, projectService, scanService } from './services';

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const PROJECT_LIST_LIMIT = 100;
const PROJECT_SCAN_LIMIT = 20;
const CANONICAL_WEAKNESS_ID = /^KISA-2021-(?:0[1-9]|[1-4][0-9])$/;
const WEAKNESS_ID_PREFIX = 'KISA-2021-';

function weaknessIdFeedback(draft: string, applied: string) {
  if (!draft || CANONICAL_WEAKNESS_ID.test(draft)) return null;
  const incomplete = WEAKNESS_ID_PREFIX.startsWith(draft)
    || /^KISA-2021-(?:0|[1-4])$/.test(draft);
  const message = incomplete
    ? '기준 ID를 끝까지 입력하면 필터가 적용됩니다.'
    : 'KISA-2021-01~49 형식만 사용할 수 있습니다.';
  return {
    invalid: !incomplete,
    message: applied ? `${message} 현재 ${applied} 필터가 유지됩니다.` : message,
  };
}

const loginSchema = z.object({
  email: z.string().email('올바른 이메일 주소를 입력해 주세요.'),
  password: z.string().min(8, '비밀번호는 8자 이상이어야 합니다.'),
});
type LoginForm = z.infer<typeof loginSchema>;

const projectSchema = z.object({
  name: z.string().min(2, '프로젝트명을 2자 이상 입력해 주세요.'),
  description: z.string().min(5, '프로젝트 설명을 5자 이상 입력해 주세요.'),
});
type ProjectForm = z.infer<typeof projectSchema>;

const userSchema = z.object({
  email: z.string().email('올바른 이메일 주소를 입력해 주세요.'),
});
type UserForm = z.infer<typeof userSchema>;

const invitationSchema = z.object({
  password: z.string().min(12, '비밀번호는 12자 이상이어야 합니다.'),
  passwordConfirm: z.string(),
}).refine((values) => values.password === values.passwordConfirm, {
  path: ['passwordConfirm'], message: '비밀번호가 일치하지 않습니다.',
});
type InvitationForm = z.infer<typeof invitationSchema>;

export function App({ initialUser }: { initialUser?: AuthenticatedUser } = {}) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<AuthenticatedUser | null | undefined>(initialUser);
  const [sessionExpired, setSessionExpired] = useState(false);
  useEffect(() => {
    if (initialUser) return;
    let active = true;
    void authService.me().then((currentUser) => {
      if (active) setUser(currentUser);
    }).catch(() => {
      if (active) setUser(null);
    });
    return () => { active = false; };
  }, [initialUser]);
  useEffect(() => {
    const expire = () => {
      setSessionExpired(true);
      setUser(null);
      queryClient.clear();
    };
    window.addEventListener('toy-sast-session-expired', expire);
    return () => window.removeEventListener('toy-sast-session-expired', expire);
  }, [queryClient]);
  useEffect(() => {
    if (!user) return;
    const remaining = new Date(user.sessionExpiresAt).getTime() - Date.now();
    const timer = window.setTimeout(() => window.dispatchEvent(new Event('toy-sast-session-expired')), Math.max(0, Math.min(remaining, 2_147_483_647)));
    return () => window.clearTimeout(timer);
  }, [user]);

  const login = async (values: LoginForm) => {
    const authenticated = await authService.login(values);
    setSessionExpired(false);
    setUser(authenticated);
  };
  const logout = () => {
    void authService.logout().catch(() => undefined).finally(() => {
      queryClient.clear();
      setSessionExpired(false);
      setUser(null);
    });
  };

  if (user === undefined) return <SessionLoading />;
  const role = user?.role ?? null;

  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/projects" replace /> : <LoginPage onLogin={login} sessionExpired={sessionExpired} />} />
      <Route path="/accept-invite" element={<AcceptInvitationPage hasActiveSession={Boolean(user)} />} />
      <Route path="/*" element={role ? (
        <AppShell user={user!} onLogout={logout}>
          <SessionExpiryNotice expiresAt={user!.sessionExpiresAt} />
          <Routes>
            <Route path="/projects" element={<ProjectsPage role={role} />} />
            <Route path="/users" element={<AdminUsersPage role={role} />} />
            <Route path="/projects/new" element={<ProjectFormPage role={role} />} />
            <Route path="/projects/:projectId/edit" element={<ProjectFormPage role={role} />} />
            <Route path="/projects/:projectId" element={<ProjectWorkspacePage role={role} />} />
            <Route path="/projects/:projectId/scans/new" element={<ScanRequestPage role={role} />} />
            <Route path="/scans/:scanId" element={<ScanDetailRoute />} />
            <Route path="/scans/:scanId/issues/:issueId" element={<IssueDetailPage />} />
            <Route path="/scans/:scanId/coverage" element={<CoveragePage />} />
            <Route path="*" element={<Navigate to="/projects" replace />} />
          </Routes>
        </AppShell>
      ) : <Navigate to="/login" replace />} />
    </Routes>
  );
}

function SessionLoading() {
  return <main className="session-loading" role="status"><div className="split-dot-loader" aria-hidden="true" /><span>로그인 상태를 확인하는 중입니다.</span></main>;
}

function SessionExpiryNotice({ expiresAt }: { expiresAt: string }) {
  const expiryTime = new Date(expiresAt).getTime();
  const [remainingMs, setRemainingMs] = useState(() => expiryTime - Date.now());
  useEffect(() => {
    const update = () => setRemainingMs(expiryTime - Date.now());
    const interval = window.setInterval(update, 30_000);
    return () => window.clearInterval(interval);
  }, [expiryTime]);
  if (remainingMs <= 0 || remainingMs > 10 * 60_000) return null;
  return <aside className="session-expiry-notice" role="status">세션이 약 {Math.max(1, Math.ceil(remainingMs / 60_000))}분 후 만료됩니다. 작업을 저장한 뒤 다시 로그인해 주세요.</aside>;
}

function LoginPage({ onLogin, sessionExpired }: { onLogin: (values: LoginForm) => Promise<void>; sessionExpired: boolean }) {
  const navigate = useNavigate();
  const [submitError, setSubmitError] = useState('');
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema), defaultValues: { email: '', password: '' },
  });
  const submit = handleSubmit(async (values) => {
    setSubmitError('');
    try {
      await onLogin(values);
      navigate('/projects');
    } catch (reason) {
      setSubmitError((reason as Error).message);
    }
  });

  return (
    <main className="login-page">
      <section className="login-story">
        <div className="login-brand"><span><ShieldCheck size={22} /></span><strong>TOY SAST</strong></div>
        <div className="login-message"><p>STATIC APPLICATION SECURITY TESTING</p><h1>코드의 위험을<br />근거로 확인합니다.</h1><span>Java · JavaScript · Python</span></div>
        <p className="login-standard">KISA 소프트웨어 개발보안 가이드 49개 항목 기반</p>
      </section>
      <section className="login-form-panel">
        <form className="login-form" onSubmit={submit} noValidate>
          <p className="eyebrow">SECURE ACCESS</p><h2>TOY SAST 로그인</h2>
          <p className="form-intro">관리자가 발급한 계정으로 로그인하세요.</p>
          {sessionExpired ? <p className="session-notice" role="status">세션이 만료되었습니다. 다시 로그인해 주세요.</p> : null}
          <Field label="이메일" error={errors.email?.message}><TextInput type="email" autoComplete="username" placeholder="name@example.com" {...register('email')} /></Field>
          <Field label="비밀번호" error={errors.password?.message}><TextInput type="password" autoComplete="current-password" placeholder="8자 이상 입력" {...register('password')} /></Field>
          {submitError ? <ErrorPanel message={submitError} /> : null}
          <Button className="full-width" disabled={isSubmitting}>{isSubmitting ? '확인 중…' : '로그인'}</Button>
          <p className="secure-note"><LockKeyhole size={15} /> 로그인 세션은 안전한 쿠키로 유지됩니다.</p>
        </form>
      </section>
    </main>
  );
}

function AcceptInvitationPage({ hasActiveSession }: { hasActiveSession: boolean }) {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') ?? '';
  const [complete, setComplete] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<InvitationForm>({
    resolver: zodResolver(invitationSchema), defaultValues: { password: '', passwordConfirm: '' },
  });
  const submit = handleSubmit(async ({ password }) => {
    setSubmitError('');
    if (!token) { setSubmitError('초대 링크에 토큰이 없습니다.'); return; }
    try {
      await authService.acceptInvitation({ token, password });
      setComplete(true);
    } catch (reason) {
      setSubmitError((reason as Error).message);
    }
  });
  return <main className="login-page"><section className="login-story"><div className="login-brand"><span><ShieldCheck size={22} /></span><strong>TOY SAST</strong></div><div className="login-message"><p>USER INVITATION</p><h1>보안 분석 결과를<br />함께 확인합니다.</h1></div><p className="login-standard">초대 링크는 설정된 유효시간 동안 한 번만 사용할 수 있습니다.</p></section><section className="login-form-panel">{complete ? <div className="login-form"><p className="eyebrow">INVITATION ACCEPTED</p><h2>비밀번호 설정 완료</h2><p className="form-intro">{hasActiveSession ? '현재 브라우저에는 다른 계정의 세션이 있습니다. 초대 계정은 로그아웃하거나 시크릿 창에서 로그인해 주세요.' : '이제 초대받은 이메일과 설정한 비밀번호로 로그인할 수 있습니다.'}</p><NavLink className="button button-primary full-width" to={hasActiveSession ? "/projects" : "/login"}>{hasActiveSession ? '현재 계정으로 돌아가기' : '로그인으로 이동'}</NavLink></div> : <form className="login-form" onSubmit={submit} noValidate><p className="eyebrow">SET PASSWORD</p><h2>비밀번호 설정</h2><p className="form-intro">계정에 사용할 비밀번호를 직접 설정해 주세요.</p>{hasActiveSession ? <p className="session-notice" role="status">현재 다른 계정으로 로그인되어 있지만 초대 비밀번호는 설정할 수 있습니다.</p> : null}<Field label="비밀번호" error={errors.password?.message}><TextInput type="password" autoComplete="new-password" placeholder="12자 이상" {...register('password')} /></Field><Field label="비밀번호 확인" error={errors.passwordConfirm?.message}><TextInput type="password" autoComplete="new-password" placeholder="한 번 더 입력" {...register('passwordConfirm')} /></Field>{submitError ? <ErrorPanel message={submitError} /> : null}<Button className="full-width" disabled={isSubmitting}>{isSubmitting ? '설정 중…' : '비밀번호 설정'}</Button></form>}</section></main>;
}

function AdminUsersPage({ role }: { role: Role }) {
  const queryClient = useQueryClient();
  const usersQuery = useQuery({ queryKey: ['admin-users'], queryFn: adminUserService.list, enabled: role === 'ADMIN' });
  const { register, handleSubmit, reset, formState: { errors } } = useForm<UserForm>({
    resolver: zodResolver(userSchema), defaultValues: { email: '' },
  });
  const creation = useMutation({
    mutationFn: (values: UserForm) => adminUserService.invite(values),
    onSuccess: () => {
      reset();
      void queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
  });
  const activation = useMutation({
    mutationFn: ({ userId, isActive }: { userId: string; isActive: boolean }) => adminUserService.setActive(userId, isActive),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['admin-users'] }),
  });
  if (role !== 'ADMIN') return <ReadOnlyNotice />;
  const generalUsers = usersQuery.data?.items.filter((user) => user.role === 'USER') ?? [];
  return <><PageHeader eyebrow="USER MANAGEMENT" title="사용자 관리" description="일반 사용자에게 초대 메일을 보내고 접근 상태를 관리합니다." />
    <section className="user-management-grid"><form className="panel form-panel user-create-form" onSubmit={handleSubmit((values) => creation.mutate(values))}><SectionHeading number="01" title="일반 사용자 초대" copy="초대받은 사용자가 이메일 링크에서 직접 비밀번호를 설정합니다." /><Field label="이메일" hint="로컬 개발 환경에서는 Mailpit 받은편지함에서 확인할 수 있습니다." error={errors.email?.message}><TextInput type="email" autoComplete="off" placeholder="user@example.com" {...register('email')} /></Field>{creation.isError ? <ErrorPanel message={(creation.error as Error).message} /> : null}<Button className="full-width" disabled={creation.isPending}>{creation.isPending ? '전송 중…' : '초대 메일 보내기'}</Button></form>
      <section className="panel user-list-panel"><div className="panel-heading"><h2>일반 사용자</h2><span>{generalUsers.length}명</span></div>{usersQuery.isError ? <ErrorPanel message={(usersQuery.error as Error).message} /> : usersQuery.isPending ? <LoadingBlock /> : generalUsers.length ? <ul className="user-list">{generalUsers.map((user) => <li key={user.id}><span><strong>{user.email}</strong><small>{user.invitationPending ? '초대 대기' : user.isActive ? '활성 계정' : '비활성 계정'} · {formatDate(user.createdAt)}</small></span>{user.invitationPending ? null : <Button type="button" variant={user.isActive ? 'danger' : 'secondary'} disabled={activation.isPending} onClick={() => activation.mutate({ userId: user.id, isActive: !user.isActive })}>{user.isActive ? '비활성화' : '활성화'}</Button>}</li>)}</ul> : <EmptyState title="등록된 일반 사용자가 없습니다." description="초대 메일을 보내면 프로젝트에 할당할 수 있습니다." />}{activation.isError ? <ErrorPanel message={(activation.error as Error).message} /> : null}</section>
    </section>
  </>;
}

function ProjectsPage({ role }: { role: Role }) {
  const [query, setQuery] = useState('');
  const [language, setLanguage] = useState('전체');
  const filters = { query, language: language === '전체' ? undefined : language, limit: PROJECT_LIST_LIMIT, offset: 0 };
  const projectsQuery = useQuery({ queryKey: ['projects', filters], queryFn: () => projectService.list(filters) });
  const projects = projectsQuery.data?.items ?? [];
  return <>
    <PageHeader eyebrow="PROJECTS" title="프로젝트" description="분석 대상 ZIP과 프로젝트별 진단 이력을 관리합니다." action={role === 'ADMIN' ? <NavLink className="button button-primary" to="/projects/new"><Plus size={17} /> 프로젝트 등록</NavLink> : null} />
    <section className="toolbar"><FilterInput value={query} onChange={setQuery} placeholder="프로젝트명 또는 설명 검색" /><select value={language} onChange={(event) => setLanguage(event.target.value)} aria-label="언어 필터"><option>전체</option><option>Java</option><option>JavaScript</option><option>Python</option></select></section>
    {projectsQuery.isError ? <ErrorPanel message={(projectsQuery.error as Error).message} /> : null}
    <section className="panel table-panel"><div className="table-meta"><strong>프로젝트 {projects.length}개</strong><span>{role === 'ADMIN' ? `검색 결과 ${projectsQuery.data?.total ?? 0}개` : '할당된 프로젝트만 표시'}</span></div>
      {projectsQuery.isPending ? <LoadingBlock /> : projects.length ? <div className="project-table" role="table" aria-label="프로젝트 목록"><div className="project-row project-row-head" role="row"><span role="columnheader">프로젝트</span><span role="columnheader">언어</span><span role="columnheader">최근 소스</span><span role="columnheader">최근 분석</span><span role="columnheader" /></div>{projects.map((project) => <ProjectRow key={project.id} project={project} />)}</div> : <EmptyState title="조건에 맞는 프로젝트가 없습니다." description="검색어 또는 언어 필터를 변경해 보세요." />}
    </section>
  </>;
}

function ProjectRow({ project }: { project: Project }) {
  const scan = project.latestScan;
  return <NavLink className="project-row" role="row" to={`/projects/${project.id}`}>
    <span role="cell"><strong>{project.name}</strong><small>{project.description}</small></span>
    <span className="language-list" role="cell">{scan?.detectedLanguages.length ? scan.detectedLanguages.map((item) => <i key={item}>{item}</i>) : <small>분석 전</small>}</span>
    <span role="cell"><strong>{scan?.archiveName ?? 'ZIP 없음'}</strong><small>{scan ? formatDate(scan.createdAt) : '소스를 업로드해 주세요.'}</small></span>
    <StatusPill status={scan?.status ?? 'NONE'} tableCell />
    <ArrowRight size={17} className="row-arrow" />
  </NavLink>;
}

function ProjectFormPage({ role }: { role: Role }) {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [memberUserIds, setMemberUserIds] = useState<string[]>([]);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const deleteTriggerRef = useRef<HTMLButtonElement>(null);
  const existingQuery = useQuery({ queryKey: ['project', projectId], queryFn: () => projectService.get(projectId!), enabled: Boolean(projectId) });
  const usersQuery = useQuery({ queryKey: ['admin-users'], queryFn: adminUserService.list, enabled: role === 'ADMIN' });
  const membersQuery = useQuery({ queryKey: ['project-members', projectId], queryFn: () => projectMemberService.get(projectId!), enabled: role === 'ADMIN' && Boolean(projectId) });
  const { register, handleSubmit, reset, formState: { errors } } = useForm<ProjectForm>({ resolver: zodResolver(projectSchema), defaultValues: { name: '', description: '' } });
  useEffect(() => {
    if (existingQuery.data) reset({ name: existingQuery.data.name, description: existingQuery.data.description });
  }, [existingQuery.data, reset]);
  useEffect(() => {
    if (!membersQuery.data) return;
    const timer = window.setTimeout(() => setMemberUserIds(membersQuery.data!.userIds), 0);
    return () => window.clearTimeout(timer);
  }, [membersQuery.data]);
  const mutation = useMutation({
    mutationFn: async (values: ProjectForm) => {
      const payload = { ...values, memberUserIds };
      return projectId ? projectService.update(projectId, payload) : projectService.create(payload);
    },
    onSuccess: (project) => {
      queryClient.setQueryData(['project', project.id], project);
      void queryClient.invalidateQueries({ queryKey: ['projects'] });
      void queryClient.invalidateQueries({ queryKey: ['project-members', project.id] });
      navigate(`/projects/${project.id}`);
    },
  });
  const deletion = useMutation({
    mutationFn: () => projectService.remove(projectId!),
    onSuccess: () => {
      queryClient.removeQueries({ queryKey: ['project', projectId] });
      queryClient.removeQueries({ queryKey: ['project-scans', projectId] });
      for (const queryKey of ['scan', 'scan-issues', 'scan-issue', 'scan-coverage', 'scan-file-children']) {
        queryClient.removeQueries({ queryKey: [queryKey] });
      }
      void queryClient.invalidateQueries({ queryKey: ['projects'] });
      navigate('/projects');
    },
  });
  if (role === 'USER') return <ReadOnlyNotice />;
  if (existingQuery.isError) return <><PageHeader eyebrow="PROJECT SETTINGS" title="프로젝트 수정" /><ErrorPanel message={(existingQuery.error as Error).message} /></>;
  if (projectId && existingQuery.isPending) return <LoadingBlock />;
  const submit = handleSubmit((values) => mutation.mutate(values));
  const closeDeleteDialog = () => {
    setDeleteOpen(false);
    window.setTimeout(() => deleteTriggerRef.current?.focus(), 0);
  };
  const dangerZone = projectId ? <section className="panel form-panel danger-zone"><div><h2>위험 구역</h2><p>프로젝트와 모든 분석 이력 및 탐지 결과가 함께 삭제됩니다.</p></div><button ref={deleteTriggerRef} className="button button-danger" type="button" onClick={() => { deletion.reset(); setDeleteOpen(true); }}>프로젝트 삭제</button></section> : null;
  const deleteDialog = deleteOpen && existingQuery.data ? <div className="dialog-backdrop"><section className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="delete-project-title" onKeyDown={(event) => {
    if (event.key === 'Escape' && !deletion.isPending) closeDeleteDialog();
    if (event.key !== 'Tab') return;
    const controls = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
    const first = controls[0];
    const last = controls.at(-1);
    if (event.shiftKey && event.target === first) { event.preventDefault(); last?.focus(); }
    if (!event.shiftKey && event.target === last) { event.preventDefault(); first?.focus(); }
  }}><h2 id="delete-project-title">프로젝트를 삭제할까요?</h2><p><strong>{existingQuery.data.name}</strong> 프로젝트와 모든 분석 이력, 탐지 결과, 파일 구조 정보가 영구적으로 삭제됩니다. 이 작업은 되돌릴 수 없습니다.</p>{deletion.isError ? <ErrorPanel message={(deletion.error as Error).message} /> : null}<div className="dialog-actions"><Button type="button" variant="secondary" autoFocus disabled={deletion.isPending} onClick={closeDeleteDialog}>취소</Button><Button type="button" variant="danger" disabled={deletion.isPending} onClick={() => deletion.mutate()}>{deletion.isPending ? '삭제 중…' : '삭제'}</Button></div></section></div> : null;
  const assignableUsers = usersQuery.data?.items.filter(
    (user) => user.role === 'USER' && (user.isActive || memberUserIds.includes(user.id)),
  ) ?? [];
  return <><PageHeader eyebrow="PROJECT SETTINGS" title={projectId ? '프로젝트 수정' : '프로젝트 등록'} description="프로젝트 기본 정보를 설정합니다. 분석 언어는 ZIP을 등록하면 자동으로 식별됩니다." backTo={projectId ? `/projects/${projectId}` : '/projects'} />
    <form className="panel form-panel" onSubmit={submit}><SectionHeading number="01" title="기본 정보" copy="업무에서 식별하기 쉬운 이름과 설명을 입력하세요." /><Field label="프로젝트명" error={errors.name?.message}><TextInput placeholder="예: 결제 서비스 API" {...register('name')} /></Field><Field label="설명" error={errors.description?.message}><textarea className="text-input textarea" placeholder="프로젝트의 목적과 분석 범위를 입력하세요." {...register('description')} /></Field><SectionHeading number="02" title="사용자 할당" copy="이 프로젝트를 조회할 일반 사용자를 선택하세요." />{usersQuery.isError || membersQuery.isError ? <ErrorPanel message={((usersQuery.error ?? membersQuery.error) as Error).message} /> : usersQuery.isPending || (projectId && membersQuery.isPending) ? <LoadingBlock /> : assignableUsers.length ? <div className="member-list">{assignableUsers.map((user) => <label className="member-option" key={user.id}><input type="checkbox" checked={memberUserIds.includes(user.id)} onChange={(event) => setMemberUserIds((current) => event.target.checked ? [...current, user.id] : current.filter((id) => id !== user.id))} /><span><strong>{user.email}</strong><small>일반 사용자 · 읽기 전용{user.isActive ? '' : ' · 비활성'}</small></span></label>)}</div> : <p className="form-empty-copy">할당할 수 있는 활성 일반 사용자가 없습니다.</p>}{mutation.isError ? <ErrorPanel message={(mutation.error as Error).message} /> : null}<div className="form-actions"><NavLink className="button button-secondary" to={projectId ? `/projects/${projectId}` : '/projects'}>취소</NavLink><Button disabled={mutation.isPending || usersQuery.isPending}>{mutation.isPending ? '저장 중…' : projectId ? '변경사항 저장' : '프로젝트 등록'}</Button></div></form>
    {dangerZone}{deleteDialog}
  </>;
}

function ProjectWorkspacePage({ role }: { role: Role }) {
  const { projectId = '' } = useParams();
  const [historyPage, setHistoryPage] = useState({ projectId, offset: 0 });
  const scanOffset = historyPage.projectId === projectId ? historyPage.offset : 0;
  const projectQuery = useQuery({ queryKey: ['project', projectId], queryFn: () => projectService.get(projectId) });
  const paging = { limit: PROJECT_SCAN_LIMIT, offset: scanOffset };
  const accessConfirmed = Boolean(projectQuery.data);
  const engineQuery = useQuery({ queryKey: ['engine'], queryFn: engineService.get, enabled: accessConfirmed });
  const scansQuery = useQuery({ queryKey: ['project-scans', projectId, paging], queryFn: () => projectService.scans(projectId, paging), enabled: accessConfirmed });
  const project = projectQuery.data;
  if (projectQuery.isError) return <><PageHeader eyebrow="PROJECT WORKSPACE" title="프로젝트" /><ErrorPanel message={(projectQuery.error as Error).message} /></>;
  if (projectQuery.isPending) return <LoadingBlock />;
  if (!project) return <NotFound />;
  const latestScan = project.latestScan ?? scansQuery.data?.items[0] ?? null;
  const scanTotal = scansQuery.data?.total ?? 0;
  return <><PageHeader eyebrow="PROJECT WORKSPACE" title={project.name} description={project.description} action={role === 'ADMIN' ? <div className="button-row"><NavLink className="button button-secondary" to={`/projects/${project.id}/edit`}>프로젝트 수정</NavLink><NavLink className="button button-primary" to={`/projects/${project.id}/scans/new`}><ScanSearch size={17} /> 분석 실행</NavLink></div> : null} />
    <section className="summary-grid"><article><span>분석 엔진</span><strong>{formatScanEngine(latestScan, engineQuery.data)}</strong><small>{formatScanRulepack(latestScan, engineQuery.data)}</small></article><article><span>자동 식별 언어</span><strong>{latestScan?.detectedLanguages.join(' · ') || '분석 전'}</strong><small>{formatLanguageCounts(latestScan)}</small></article><article><span>최근 분석</span><StatusPill status={latestScan?.status ?? 'NONE'} />{latestScan ? <small>{formatDate(latestScan.updatedAt)}</small> : null}</article></section>
    {!latestScan && engineQuery.isError ? <ErrorPanel message={(engineQuery.error as Error).message} /> : null}
    <section className="workspace-grid"><article className="panel"><div className="panel-heading"><h2>최근 소스</h2><span>관리자 ZIP</span></div>{latestScan ? <dl className="detail-list"><div><dt>파일명</dt><dd>{latestScan.archiveName}</dd></div><div><dt>ZIP 항목</dt><dd>{formatCount(latestScan.archiveFileCount)}</dd></div><div><dt>분석 파일</dt><dd>{formatCount(latestScan.analysisFileCount)}</dd></div><div><dt>마지막 갱신</dt><dd>{formatDate(latestScan.updatedAt)}</dd></div></dl> : <EmptyState title="업로드된 소스가 없습니다." description="첫 ZIP 분석을 실행하면 파일 정보가 표시됩니다." />}</article><article className="panel"><div className="panel-heading"><h2>분석 이력</h2><span>{scanTotal}건</span></div>{scansQuery.isError ? <ErrorPanel message={(scansQuery.error as Error).message} /> : scansQuery.isPending ? <LoadingBlock /> : scansQuery.data?.items.length ? <><div className="scan-history">{scansQuery.data.items.map((scan) => <ScanHistoryLink key={scan.scanId} scan={scan} />)}</div><HistoryPagination offset={scanOffset} limit={scansQuery.data.limit} total={scanTotal} onPageChange={(offset) => setHistoryPage({ projectId, offset })} /></> : <EmptyState title="분석 이력이 없습니다." description={role === 'ADMIN' ? '첫 ZIP 분석을 실행해 보세요.' : '관리자가 분석을 실행하면 결과가 표시됩니다.'} />}</article></section>
  </>;
}

function ScanHistoryLink({ scan }: { scan: ScanSummary }) {
  return <NavLink className="scan-link" to={`/scans/${scan.scanId}`}><span><strong>{scan.archiveName}</strong><small>{scan.detectedLanguages.join(' · ') || '언어 식별 전'} · {formatDate(scan.createdAt)}</small></span><StatusPill status={scan.status} /><ArrowRight size={18} /></NavLink>;
}

function HistoryPagination({ offset, limit, total, onPageChange }: { offset: number; limit: number; total: number; onPageChange: (offset: number) => void }) {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  return <nav className="history-pagination" aria-label="분석 이력 페이지"><button type="button" onClick={() => onPageChange(Math.max(0, offset - limit))} disabled={offset === 0}>이전</button><span aria-live="polite">{currentPage} / {totalPages}</span><button type="button" onClick={() => onPageChange(offset + limit)} disabled={offset + limit >= total}>다음</button></nav>;
}

function ScanRequestPage({ role }: { role: Role }) {
  const { projectId = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const projectQuery = useQuery({ queryKey: ['project', projectId], queryFn: () => projectService.get(projectId) });
  const engineQuery = useQuery({ queryKey: ['engine'], queryFn: engineService.get });
  const project = projectQuery.data;
  const mutation = useMutation({
    mutationFn: () => file && project ? scanService.create(project.id, file) : Promise.reject(new Error('ZIP 파일을 선택해 주세요.')),
    onSuccess: (scan) => {
      queryClient.setQueryData(['scan', scan.scanId], scan);
      void queryClient.invalidateQueries({ queryKey: ['projects'] });
      void queryClient.invalidateQueries({ queryKey: ['project', scan.projectId] });
      void queryClient.invalidateQueries({ queryKey: ['project-scans', scan.projectId] });
      navigate(`/scans/${scan.scanId}`, { state: { analysisStarted: true } });
    },
    onError: (reason: Error) => setError(reason.message),
  });
  if (role !== 'ADMIN') return <ReadOnlyNotice />;
  if (projectQuery.isError) return <><PageHeader eyebrow="NEW SECURITY SCAN" title="분석 실행 요청" /><ErrorPanel message={(projectQuery.error as Error).message} /></>;
  if (projectQuery.isPending) return <LoadingBlock />;
  if (!project) return <NotFound />;

  const chooseFiles = (files: File[]) => {
    if (files.length !== 1) { setFile(null); setError('ZIP 파일을 한 개만 등록해 주세요.'); return; }
    const [nextFile] = files;
    if (!nextFile.name.toLowerCase().endsWith('.zip')) { setFile(null); setError('ZIP 형식의 파일만 업로드할 수 있습니다.'); return; }
    if (nextFile.size === 0) { setFile(null); setError('비어 있는 ZIP 파일은 업로드할 수 없습니다.'); return; }
    if (nextFile.size > MAX_UPLOAD_BYTES) { setFile(null); setError('ZIP 파일은 50 MiB 이하여야 합니다.'); return; }
    setError('');
    setFile(nextFile);
  };
  const onInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    chooseFiles(Array.from(event.target.files ?? []));
    event.target.value = '';
  };
  const preventDragNavigation = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
  };
  const onDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setDragActive(false);
    chooseFiles(Array.from(event.dataTransfer.files));
  };
  const engine = engineQuery.data;
  return <><PageHeader eyebrow="NEW SECURITY SCAN" title="분석 실행 요청" description={`${project.name}의 새 ZIP 소스를 안전한 작업공간에서 분석합니다.`} backTo={`/projects/${project.id}`} />
    <section className="scan-request-grid"><form className="panel form-panel" onSubmit={(event) => { event.preventDefault(); mutation.mutate(); }}><SectionHeading number="01" title="ZIP 소스 선택" copy="ZIP을 선택하거나 이 영역으로 끌어오면 분석 언어를 자동으로 식별합니다." /><label className={`file-drop ${dragActive ? 'file-drop-active' : ''}`} onDragEnter={(event) => { preventDragNavigation(event); setDragActive(true); }} onDragOver={preventDragNavigation} onDragLeave={(event) => { preventDragNavigation(event); if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragActive(false); }} onDrop={onDrop}><input type="file" accept=".zip,application/zip" onChange={onInputChange} aria-label="분석할 ZIP 파일" /><FileArchive size={28} /><strong>{dragActive ? '여기에 ZIP을 놓으세요' : file ? '다른 ZIP 선택' : 'ZIP 파일 선택 또는 끌어놓기'}</strong><span>ZIP 한 개 · 최대 50 MiB · 서버에서 압축 해제 안전성을 다시 검증합니다.</span></label>{file ? <FileSummary file={file} /> : null}{error ? <ErrorPanel message={error} /> : null}<div className="form-actions"><NavLink className="button button-secondary" to={`/projects/${project.id}`}>취소</NavLink><Button disabled={!file || mutation.isPending}>{mutation.isPending ? '업로드 중…' : '분석 실행'}</Button></div></form>
      <aside className="panel execution-summary"><p className="eyebrow">EXECUTION SUMMARY</p><h2>실행 기준</h2><dl className="detail-list"><div><dt>프로젝트</dt><dd>{project.name}</dd></div><div><dt>입력 방식</dt><dd>관리자 ZIP 업로드</dd></div><div><dt>분석 언어</dt><dd>ZIP에서 자동 식별</dd></div><div><dt>분석 엔진</dt><dd>{formatEngine(engine)}</dd></div><div><dt>룰팩</dt><dd>{engine ? `${engine.rulepackName} ${engine.rulepackVersion}` : '불러오는 중'}</dd></div><div><dt>등록 규칙</dt><dd>{engine ? `${engine.registeredRuleCount}개` : '불러오는 중'}</dd></div></dl>{engineQuery.isError ? <ErrorPanel message={(engineQuery.error as Error).message} /> : null}<p className="summary-note"><ShieldCheck size={17} /> 각 기준은 ZIP에서 식별된 언어별로 탐지됨, 탐지되지 않음, 자동 탐지 미지원 또는 검사 실패로 표시됩니다.</p></aside>
    </section>
  </>;
}

function ScanDetailRoute() {
  const { scanId = '' } = useParams();
  return <ScanDetailPage key={scanId} />;
}

function ScanDetailPage() {
  const { scanId = '' } = useParams();
  const location = useLocation();
  const queryClient = useQueryClient();
  const fileTreeTriggerRef = useRef<HTMLButtonElement>(null);
  const [severity, setSeverity] = useState<IssueListFilters['severity']>();
  const [language, setLanguage] = useState('');
  const [weaknessIdDraft, setWeaknessIdDraft] = useState('');
  const [appliedWeaknessId, setAppliedWeaknessId] = useState('');
  const [fileSelection, setFileSelection] = useState<FileSelection | null>(null);
  const [fileTreeOpen, setFileTreeOpen] = useState(false);
  const [cursors, setCursors] = useState<string[]>([]);
  const isMobileFileTree = useMediaQuery('(max-width: 820px)');
  const prefersReducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)');
  const startedFromRequest = Boolean((location.state as { analysisStarted?: boolean } | null)?.analysisStarted);
  const [observedActiveScanId, setObservedActiveScanId] = useState<string | null>(startedFromRequest ? scanId : null);
  const [completionOverlay, setCompletionOverlay] = useState<{ scanId: string; stage: 'visible' | 'exiting' | 'hidden' }>({ scanId, stage: 'visible' });
  const invalidatedTerminalScans = useRef(new Set<string>());
  const scanQuery = useQuery({ queryKey: ['scan', scanId], queryFn: () => scanService.get(scanId), refetchInterval: (activeQuery) => ['COMPLETED', 'FAILED'].includes(activeQuery.state.data?.status ?? '') ? false : 1000 });
  const scan = scanQuery.data;
  const complete = scan?.status === 'COMPLETED';
  const canReadResults = true;
  const filters = useMemo<IssueListFilters>(() => ({
    severity, language: language || undefined, weaknessId: appliedWeaknessId || undefined,
    path: fileSelection?.pathScope === 'ARCHIVE' ? undefined : fileSelection?.path,
    pathScope: fileSelection?.pathScope === 'ARCHIVE' ? undefined : fileSelection?.pathScope,
    limit: 50, cursor: cursors.at(-1),
  }), [appliedWeaknessId, cursors, fileSelection, language, severity]);
  const issuesQuery = useQuery({ queryKey: ['scan-issues', scanId, filters], queryFn: () => scanService.issues(scanId, filters), enabled: Boolean(complete) });
  useEffect(() => {
    if (!scan || !['COMPLETED', 'FAILED'].includes(scan.status) || invalidatedTerminalScans.current.has(scan.scanId)) return;
    invalidatedTerminalScans.current.add(scan.scanId);
    void queryClient.invalidateQueries({ queryKey: ['projects'] });
    void queryClient.invalidateQueries({ queryKey: ['project', scan.projectId] });
    void queryClient.invalidateQueries({ queryKey: ['project-scans', scan.projectId] });
  }, [queryClient, scan]);
  useEffect(() => {
    if (!scanQuery.data || ['COMPLETED', 'FAILED'].includes(scanQuery.data.status) || observedActiveScanId === scanId) return;
    const timer = window.setTimeout(() => { setObservedActiveScanId(scanId); setCompletionOverlay({ scanId, stage: 'visible' }); }, 0);
    return () => window.clearTimeout(timer);
  }, [observedActiveScanId, scanId, scanQuery.data]);
  useEffect(() => {
    const issuesSettled = Boolean(issuesQuery.data || issuesQuery.isError);
    if (!complete || scan?.progressPercent !== 100 || observedActiveScanId !== scanId || !issuesSettled) return;
    const fadeTimer = window.setTimeout(() => setCompletionOverlay({ scanId, stage: 'exiting' }), prefersReducedMotion ? 0 : 160);
    return () => window.clearTimeout(fadeTimer);
  }, [complete, issuesQuery.data, issuesQuery.isError, observedActiveScanId, prefersReducedMotion, scan?.progressPercent, scanId]);
  useEffect(() => {
    if (completionOverlay.scanId !== scanId || completionOverlay.stage !== 'exiting') return;
    const fallback = window.setTimeout(() => setCompletionOverlay({ scanId, stage: 'hidden' }), 220);
    return () => window.clearTimeout(fallback);
  }, [completionOverlay, scanId]);
  if (scanQuery.isError) return <><PageHeader eyebrow="SCAN RESULT" title="분석 상세" /><ErrorPanel message={(scanQuery.error as Error).message} /></>;
  const completionStage = completionOverlay.scanId === scanId ? completionOverlay.stage : 'visible';
  const showAnalysisOverlay = Boolean(scan && scan.status !== 'FAILED' && (!['COMPLETED'].includes(scan.status) || (observedActiveScanId === scanId && completionStage !== 'hidden')));
  const resetCursor = () => setCursors([]);
  const weaknessFeedback = weaknessIdFeedback(weaknessIdDraft, appliedWeaknessId);
  const updateWeaknessIdDraft = (value: string) => {
    setWeaknessIdDraft(value);
    if (value === '' || CANONICAL_WEAKNESS_ID.test(value)) {
      setAppliedWeaknessId(value);
      resetCursor();
    }
  };
  const selectFile = (selection: FileSelection) => {
    setFileSelection(selection);
    resetCursor();
    setFileTreeOpen(false);
    if (isMobileFileTree) window.setTimeout(() => fileTreeTriggerRef.current?.focus(), 0);
  };
  return <><PageHeader eyebrow="SCAN ISSUES" title={scan ? `분석 ${scan.scanId.slice(0, 8)}` : '분석 상세'} description="검증된 자동 탐지 룰이 실제 코드 위치를 가리킨 이슈만 표시합니다." backTo={scan ? `/projects/${scan.projectId}` : '/projects'} action={scan ? <StatusPill status={scan.status} /> : null} />
    <section className="panel scan-result-panel" aria-busy={showAnalysisOverlay}>{showAnalysisOverlay && scan ? <AnalysisOverlay percent={scan.progressPercent} status={scan.status} exiting={completionStage === 'exiting'} onTransitionEnd={() => setCompletionOverlay({ scanId, stage: 'hidden' })} /> : null}<div className="scan-result-content" inert={showAnalysisOverlay ? true : undefined} aria-hidden={showAnalysisOverlay ? true : undefined}>{scan?.status === 'FAILED' ? <ErrorPanel message={scan.message} /> : null}{scan?.status === 'COMPLETED' && scan.message.includes('완전히 해석하지 못했습니다') ? <p className="analysis-warning-notice" role="status">{scan.message}</p> : null}<div className="scan-summary-row"><div><span>자동 식별 언어</span><strong>{scan?.detectedLanguages.join(' · ') || '식별 중'}</strong></div><div><span>분석 엔진</span><strong>{scan ? formatScanEngine(scan) : '불러오는 중'}</strong></div><div><span>실행 규칙</span><strong>{scan ? formatExecutedRuleCount(scan) : '집계 중'}</strong></div></div><div className={`scan-result-workspace ${complete && canReadResults ? 'scan-result-workspace-with-tree' : ''}`}>{complete && canReadResults ? <div className="file-tree-disclosure"><button ref={fileTreeTriggerRef} type="button" className="file-tree-disclosure-trigger" aria-expanded={!isMobileFileTree || fileTreeOpen} aria-controls={`scan-file-tree-${scanId}`} onClick={() => setFileTreeOpen((open) => !open)}>파일 구조{fileSelection ? <span>{fileSelection.pathScope === 'ARCHIVE' ? fileSelection.archiveName : fileSelection.path}</span> : null}</button><div id={`scan-file-tree-${scanId}`} className="file-tree-disclosure-content">{!isMobileFileTree || fileTreeOpen ? <FileTree scanId={scanId} archiveName={scan.archiveName} selection={fileSelection} onSelectionChange={selectFile} /> : null}</div></div> : null}<div className="scan-results-column">{fileSelection ? <div className="file-selection-summary" role="status"><span><strong>{fileSelection.pathScope === 'ARCHIVE' ? '전체' : fileSelection.pathScope === 'FILE' ? '파일' : '폴더 전체'}</strong>{fileSelection.pathScope === 'ARCHIVE' ? fileSelection.archiveName : fileSelection.path}<small> · 이슈 {issuesQuery.data?.total ?? 0}건</small></span><button type="button" onClick={() => { setFileSelection(null); resetCursor(); }}>선택 해제</button></div> : null}<div className="issue-toolbar"><div className="issue-filter-field"><FilterInput value={weaknessIdDraft} onChange={updateWeaknessIdDraft} placeholder="기준 ID (예: KISA-2021-05)" describedBy={weaknessFeedback ? 'weakness-id-filter-hint' : undefined} invalid={weaknessFeedback?.invalid} />{weaknessFeedback ? <small id="weakness-id-filter-hint" className={weaknessFeedback.invalid ? 'issue-filter-hint issue-filter-hint-invalid' : 'issue-filter-hint'}>{weaknessFeedback.message}</small> : null}</div><select value={severity ?? ''} onChange={(event) => { setSeverity((event.target.value || undefined) as IssueListFilters['severity']); resetCursor(); }} aria-label="위험도 필터"><option value="">전체 위험도</option><option value="ERROR">높음</option><option value="WARNING">중간</option><option value="INFO">낮음</option></select><select value={language} onChange={(event) => { setLanguage(event.target.value); resetCursor(); }} aria-label="언어 필터"><option value="">전체 언어</option>{scan?.detectedLanguages.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>{issuesQuery.isError ? <ErrorPanel message={(issuesQuery.error as Error).message} /> : complete && !issuesQuery.isPending && issuesQuery.data ? <IssueListView scanId={scanId} issues={issuesQuery.data} selection={fileSelection} canBack={cursors.length > 0} onBack={() => setCursors((value) => value.slice(0, -1))} onNext={() => issuesQuery.data?.nextCursor && setCursors((value) => [...value, issuesQuery.data!.nextCursor!])} /> : complete ? <LoadingBlock /> : !scan ? <LoadingBlock /> : null}</div></div></div></section>
  </>;
}

function IssueListView({ scanId, issues, selection, canBack, onBack, onNext }: { scanId: string; issues: Awaited<ReturnType<typeof scanService.issues>>; selection: FileSelection | null; canBack: boolean; onBack: () => void; onNext: () => void }) {
  if (!issues.issueModelAvailable) return <Navigate to={`/scans/${scanId}/coverage`} replace />;
  const stats = issues.stats;
  const hasLegacyReviewSignal = ('reviewSignalCount' in stats && (stats.reviewSignalCount ?? 0) > 0)
    || issues.items.some((issue) => issue.resultStatus === 'REVIEW_REQUIRED');
  return <>{hasLegacyReviewSignal ? <p className="legacy-result-notice" role="status">이전 결과 모델의 검토 신호가 포함되어 있습니다. 현재 기준으로 다시 분석해 주세요.</p> : null}<div className="issue-stats" aria-label="이슈 집계"><span><strong>탐지 이슈</strong><b>{stats.detectedIssueCount}</b></span><span><strong>위험도</strong><small>매우 높음 0 · 높음 {stats.severityCounts.ERROR} · 중간 {stats.severityCounts.WARNING} · 낮음 {stats.severityCounts.INFO}</small></span><NavLink to={`/scans/${scanId}/coverage`}>검사 기준 리스트</NavLink></div>{!issues.items.length ? <EmptyState title={selection ? '선택한 경로에 이슈가 없습니다.' : '탐지된 이슈가 없습니다.'} description="필터를 바꾸거나 검사 기준 리스트에서 전체 기준별 결과를 확인해 보세요." /> : <section className="results-table issue-table" aria-labelledby="issue-list-title"><h2 id="issue-list-title" className="visually-hidden">분석 이슈 목록</h2><div className="issue-row issue-head" aria-hidden="true"><span>기준</span><span>이슈</span><span>위치</span><span>판정</span><span>위험도</span><span>신뢰도</span></div><ul className="issue-list" aria-label="분석 이슈 목록">{issues.items.map((issue) => <li key={issue.issueId}><IssueRow scanId={scanId} issue={issue} /></li>)}</ul></section>}<nav className="issue-pagination" aria-label="이슈 페이지"><button type="button" onClick={onBack} disabled={!canBack}>이전</button><span>{issues.total}건 중 현재 페이지</span><button type="button" onClick={onNext} disabled={!issues.nextCursor}>다음</button></nav></>;
}

function IssueRow({ scanId, issue }: { scanId: string; issue: IssueListItem }) {
  return <NavLink className="issue-row" to={`/scans/${scanId}/issues/${issue.issueId}`}><span className="issue-cell rule-number"><span className="issue-label">기준</span>SW 개발보안 가이드 · {String(issue.weaknessNumber).padStart(2, '0')}번<small>보안약점 기준 번호</small></span><span className="issue-cell"><span className="issue-label">이슈</span><strong>{issue.weaknessName}</strong><small>{issue.ruleId}</small></span><span className="issue-cell"><span className="issue-label">위치</span><code>{issue.path}:{issue.startLine}</code><small>{issue.language}</small></span><span className="issue-cell issue-status issue-status-stacked"><span className="issue-label">판정</span><StatusPill status={issue.resultStatus} /></span><span className="issue-cell issue-status issue-status-stacked"><span className="issue-label">위험도</span><StatusPill status={issue.severity} /></span><span className="issue-cell issue-status issue-status-stacked"><span className="issue-label">신뢰도</span><StatusPill status={issue.confidence} /></span></NavLink>;
}

function IssueDetailPage() {
  const { scanId = '', issueId = '' } = useParams();
  const isDemo = scanId === demoScan.scanId;
  const scanQuery = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scanService.get(scanId),
    refetchInterval: (activeQuery) => activeQuery.state.data?.status === 'COMPLETED' || activeQuery.state.data?.status === 'FAILED' ? false : 1000,
  });
  const query = useQuery({ queryKey: ['scan-issue', scanId, issueId], queryFn: () => scanService.issue(scanId, issueId), enabled: Boolean(scanQuery.data?.status === 'COMPLETED' && !isDemo) });
  if (scanQuery.isError) return <ErrorPanel message={(scanQuery.error as Error).message} />;
  if (isDemo) return <Navigate to={`/scans/${scanId}/coverage`} replace />;
  if (scanQuery.data?.status !== 'COMPLETED') return <ScanNotReady scan={scanQuery.data} />;
  if (query.isError) return <ErrorPanel message={(query.error as Error).message} />;
  if (!query.data || !scanQuery.data) return <LoadingBlock />;
  return <IssueDetailView issue={query.data} />;
}

function IssueDetailView({ issue }: { issue: IssueDetail }) {
  const displayValue = (value: string | number | null | undefined) => value == null || value === '' ? '정보 없음' : value;
  const legacyReviewSignal = issue.resultStatus === 'REVIEW_REQUIRED';
  const resultLabel = legacyReviewSignal ? '이전 모델의 검토 신호' : '탐지됨';
  return <>
    <PageHeader eyebrow="SW 개발보안 가이드" title={issue.weakness.name} description={`${issue.weakness.category} · ${issue.weakness.number}번`} backTo={`/scans/${issue.scanId}`} action={<StatusPill status={issue.resultStatus} />} />
    {legacyReviewSignal ? <p className="legacy-result-notice" role="status">이전 결과 모델의 검토 신호입니다. 확정 탐지로 해석하지 말고 현재 기준으로 다시 분석해 주세요.</p> : null}
    <section className="finding-layout">
      <article className="panel">
        <div className="panel-heading"><h2>{legacyReviewSignal ? '이전 모델의 검토 신호' : '탐지 이슈'}</h2><StatusPill status={issue.resultStatus} /></div>
        <dl className="detail-list">
          <div><dt>파일 경로</dt><dd><code>{issue.location.path}:{issue.location.startLine}</code></dd></div>
          <div><dt>언어</dt><dd>{issue.rule.language}</dd></div>
          <div><dt>위험도</dt><dd><StatusPill status={issue.rule.severity} /></dd></div>
          <div><dt>신뢰도</dt><dd><StatusPill status={issue.confidence} /></dd></div>
        </dl>
        <h3 className="detail-copy-title">보안약점 설명</h3><p className="reason-copy">{issue.weakness.description}</p>
        <h3 className="detail-copy-title">탐지 이유</h3><p className="reason-copy">{issue.rule.description || issue.detectionRationale}</p>
      </article>
      <article className="panel issue-guidance">
        <div className="panel-heading"><h2>수정 방법</h2><span>{resultLabel}</span></div>
        <div className="finding-card"><code>{issue.location.path}:{issue.location.startLine}:{issue.location.startColumn}–{issue.location.endLine}:{issue.location.endColumn}</code><p>{issue.rule.message}</p><small>원본 소스: 미보관</small></div>
        <section aria-labelledby="automation-limitation-title"><h3 id="automation-limitation-title" className="detail-copy-title">추가 확인사항</h3><p className="reason-copy">{issue.automationLimitation}</p></section>
        <section aria-labelledby="remediation-title"><h3 id="remediation-title" className="detail-copy-title">수정 방법</h3><p className="reason-copy">{issue.remediation}</p></section>
        <section aria-labelledby="safe-example-title"><h3 id="safe-example-title" className="detail-copy-title">안전한 구현 예시</h3><pre><code>{issue.safeImplementationExample}</code></pre></section>
        <section aria-labelledby="references-title"><h3 id="references-title" className="detail-copy-title">참고자료</h3><ul>{issue.references.map((reference) => <li key={reference}><a href={reference} target="_blank" rel="noopener noreferrer">{reference}</a></li>)}</ul></section>
        <details className="technical-details"><summary>기술 정보</summary><dl className="detail-list"><div><dt>내부 기준 ID</dt><dd><code>{issue.weakness.weaknessId}</code></dd></div><div><dt>룰 ID</dt><dd><code>{issue.rule.ruleId}</code></dd></div><div><dt>이슈 ID</dt><dd><code className="identifier-value">{issue.issueId}</code></dd></div><div><dt>fingerprint</dt><dd><code>{issue.fingerprint}</code></dd></div><div><dt>엔진 snapshot</dt><dd>{issue.engineSnapshot.engineName} {issue.engineSnapshot.engineVersion} · {issue.engineSnapshot.rulepackName} {issue.engineSnapshot.rulepackVersion}</dd></div><div><dt>CWE</dt><dd>{displayValue(issue.rule.cweId)}</dd></div></dl></details>
      </article>
    </section>
  </>;
}

function CoveragePage() {
  const { scanId = '' } = useParams();
  const scanQuery = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scanService.get(scanId),
    refetchInterval: (activeQuery) => activeQuery.state.data?.status === 'COMPLETED' || activeQuery.state.data?.status === 'FAILED' ? false : 1000,
  });
  const coverageQuery = useQuery({ queryKey: ['scan-coverage', scanId], queryFn: () => scanService.coverage(scanId), enabled: Boolean(scanQuery.data?.status === 'COMPLETED') });
  if (scanQuery.isError) return <ErrorPanel message={(scanQuery.error as Error).message} />;
  if (scanQuery.data?.status !== 'COMPLETED') return <ScanNotReady scan={scanQuery.data} />;
  if (coverageQuery.isError) return <ErrorPanel message={(coverageQuery.error as Error).message} />;
  if (!coverageQuery.data) return <LoadingBlock />;
  return <CoverageView coverage={coverageQuery.data} />;
}

function CoverageView({ coverage }: { coverage: ScanCoverage }) {
  const detectedCount = coverage.items.filter((item) => item.languages?.some((language) => language.resultStatus === 'DETECTED') ?? item.resultStatus === 'DETECTED').length;
  const detectedLanguages = [...new Set(coverage.items.flatMap((item) => item.languages?.map((language) => language.language) ?? []))];
  const legacy = coverage.coverageModelVersion !== 2;
  return <><PageHeader eyebrow="COVERAGE" title="검사 기준 리스트" description="한국인터넷진흥원(KISA) SW 개발보안 가이드의 기준별 언어 결과입니다." backTo={`/scans/${coverage.scanId}`} /><section className="panel table-panel">{legacy ? <p className="legacy-result-notice" role="status">이전 결과 모델로 생성됨 · 현재 기준으로 다시 분석 필요</p> : null}<div className="table-meta"><strong>총 49개 보안약점</strong><span>탐지 기준 {detectedCount}개 · 분석 대상 언어 {detectedLanguages.length ? detectedLanguages.join(' · ') : '확인 전'}</span></div><div className="results-table coverage-table" role="table" aria-label="검사 기준 리스트, 총 49개 보안약점"><div className="coverage-row coverage-head" role="row"><span role="columnheader">번호</span><span role="columnheader">검사 기준</span><span role="columnheader">언어별 자동 탐지 결과</span><span role="columnheader">이슈</span></div>{coverage.items.map((item) => <CoverageRow item={item} key={item.weaknessId} />)}</div></section></>;
}

function CoverageRow({ item }: { item: ScanCoverage['items'][number] }) {
  const languages = item.languages ?? (item.supportStatus && item.resultStatus ? [{ language: '전체', supportStatus: item.supportStatus, resultStatus: item.resultStatus, executedRuleCount: 0, findingCount: item.findingCount, reason: item.reason }] : []);
  return <div className="coverage-row" role="row"><span className="coverage-cell coverage-number rule-number" role="cell"><span className="coverage-label">번호</span>{String(item.number).padStart(2, '0')}번</span><span className="coverage-cell coverage-criterion" role="cell"><span className="coverage-label">검사 기준</span><strong>{item.name}</strong><small>SW 개발보안 가이드 · {item.number}번 · {item.category}</small></span><span className="coverage-cell coverage-languages" role="cell"><span className="coverage-label">언어별 자동 탐지 결과</span>{languages.map((language) => <span className="coverage-language" key={language.language}><strong>{language.language}</strong><StatusPill status={language.resultStatus} />{language.resultStatus === 'DETECTED' ? <small>{language.findingCount}건</small> : language.resultStatus === 'CHECK_FAILED' ? <small title={language.reason}>{language.reason}</small> : null}</span>)}</span><span className="coverage-cell coverage-count" role="cell"><span className="coverage-label">이슈</span>{item.findingCount}건</span></div>;
}

function ScanNotReady({ scan }: { scan: ScanProgress | undefined }) {
  if (!scan) return <LoadingBlock />;
  if (scan.status === 'FAILED') return <><PageHeader eyebrow="SCAN RESULT" title="분석 상세" action={<StatusPill status={scan.status} />} /><ErrorPanel message={scan.message} /></>;
  return <><PageHeader eyebrow="SCAN RESULT" title="분석 준비 중" description="분석이 완료되면 이 화면의 결과를 자동으로 불러옵니다." action={<StatusPill status={scan.status} />} /><section className="panel scan-result-panel" aria-busy="true"><AnalysisOverlay percent={scan.progressPercent} status={scan.status} /><div className="scan-result-content" aria-hidden="true" /></section></>;
}

function isTerminalScan(scan: ScanSummary) { return scan.status === 'COMPLETED' || scan.status === 'FAILED'; }
function formatEngine(engine: EngineSnapshot | null | undefined) { return engine ? `${engine.engineName} ${engine.engineVersion}` : '불러오는 중'; }
function formatScanEngine(scan: ScanSummary | null, currentEngine?: EngineSnapshot) {
  if (!scan) return formatEngine(currentEngine);
  if (scan.engineSnapshot) return formatEngine(scan.engineSnapshot);
  return isTerminalScan(scan) ? '기록 없음 · 레거시 분석' : '스냅샷 준비 중';
}
function formatScanRulepack(scan: ScanSummary | null, currentEngine?: EngineSnapshot) {
  if (!scan) return currentEngine ? `${currentEngine.rulepackName} ${currentEngine.rulepackVersion}` : '엔진 정보를 불러오는 중';
  if (scan.engineSnapshot) return `${scan.engineSnapshot.rulepackName} ${scan.engineSnapshot.rulepackVersion}`;
  return isTerminalScan(scan) ? '완료 당시 엔진 스냅샷 없음' : '작업 엔진 정보를 기록하는 중';
}
function formatExecutedRuleCount(scan: ScanSummary) {
  if (scan.engineSnapshot?.executedRuleCount != null) return `${scan.engineSnapshot.executedRuleCount}개`;
  return isTerminalScan(scan) ? '기록 없음' : '집계 중';
}
function formatLanguageCounts(scan: ScanSummary | null) { return !scan || !scan.detectedLanguages.length ? '분석하면 자동으로 표시됩니다.' : scan.detectedLanguages.map((language) => `${language} ${scan.languageFileCounts[language] ?? 0}개`).join(' · '); }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat('ko-KR', { dateStyle: 'medium', timeStyle: 'short' }).format(date); }
function formatCount(value: number | null) { return value == null ? '집계 전' : `${value}개`; }
function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(() => typeof window.matchMedia === 'function' && window.matchMedia(query).matches);
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return undefined;
    const media = window.matchMedia(query);
    const update = () => setMatches(media.matches);
    update();
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, [query]);
  return matches;
}
function LoadingBlock() { return <div className="skeleton-block" aria-label="불러오는 중" />; }
function SectionHeading({ number, title, copy }: { number: string; title: string; copy: string }) { return <div className="section-heading"><span>{number}</span><div><h2>{title}</h2><p>{copy}</p></div></div>; }
function ReadOnlyNotice() { return <><PageHeader eyebrow="LIMITED ACCESS" title="제한된 권한" /><ErrorPanel message="일반 사용자는 할당된 프로젝트를 조회할 수 있으며 등록·수정·삭제·분석 실행은 할 수 없습니다." /></>; }
function NotFound() { return <><PageHeader eyebrow="NOT FOUND" title="대상을 찾을 수 없습니다." /><EmptyState title="요청한 데이터가 없습니다." description="프로젝트 목록으로 돌아가 다시 선택해 주세요." /></>; }
