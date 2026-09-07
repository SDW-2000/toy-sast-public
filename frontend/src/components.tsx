import { cloneElement, forwardRef, isValidElement, useId, useLayoutEffect, useRef, useState } from 'react';
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  AlertTriangle, ArrowLeft, ChevronRight, FileArchive, FolderKanban,
  LogOut, Search, ShieldCheck, SlidersHorizontal, UserRound,
} from 'lucide-react';
import type { AuthenticatedUser, ScanStatus } from './domain';

export function Button({ className = '', variant = 'primary', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger' }) {
  return <button className={`button button-${variant} ${className}`} {...props} />;
}

export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: ReactNode }) {
  const fieldId = useId();
  const labelId = `${fieldId}-label`;
  const describedBy = error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined;
  const control = isValidElement<Record<string, unknown>>(children)
    ? cloneElement(children, {
        'aria-labelledby': labelId,
        'aria-describedby': describedBy,
        'aria-invalid': error ? true : undefined,
      })
    : children;
  return (
    <div className={`field ${error ? 'field-error' : ''}`}>
      <span id={labelId} className="field-label">{label}</span>
      <div className="field-control">{control}</div>
      {error ? <span id={`${fieldId}-error`} className="field-message error-message">{error}</span> : null}
      {!error && hint ? <span id={`${fieldId}-hint`} className="field-message">{hint}</span> : null}
    </div>
  );
}

/**
 * Keeps the browser's input control (and therefore RHF refs, selection, IME and
 * autofill) authoritative.  The drawn caret is only a focused collapsed-range
 * enhancement; all ambiguous states intentionally fall back to the native caret.
 */
export const TextInput = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function TextInput({ className = '', type = 'text', onSelect, onCompositionStart, onCompositionEnd, onKeyDown, onKeyUp, onPointerDown, onFocus, onBlur, onInput, onScroll, ...props }, forwardedRef) {
    const inputRef = useRef<HTMLInputElement>(null);
    const mirrorRef = useRef<HTMLSpanElement>(null);
    const [caret, setCaret] = useState<{ left: number; visible: boolean; motion: boolean }>({ left: 0, visible: false, motion: false });
    const composing = useRef(false);
    const caretMotion = useRef(false);
    const setRefs = (node: HTMLInputElement | null) => {
      inputRef.current = node;
      if (typeof forwardedRef === 'function') forwardedRef(node);
      else if (forwardedRef) forwardedRef.current = node;
    };
    const updateCaret = (motion = false) => {
      const input = inputRef.current;
      const mirror = mirrorRef.current;
      if (!input || !mirror || document.activeElement !== input || composing.current || input.selectionStart == null || input.selectionStart !== input.selectionEnd) {
        setCaret((current) => current.visible ? { ...current, visible: false } : current);
        return;
      }
      const selection = input.selectionStart;
      const rawValue = input.value.slice(0, selection);
      mirror.textContent = type === 'password' ? '•'.repeat(rawValue.length) : rawValue;
      const style = getComputedStyle(input);
      mirror.style.fontFamily = style.fontFamily;
      mirror.style.fontSize = style.fontSize;
      mirror.style.fontStyle = style.fontStyle;
      mirror.style.fontWeight = style.fontWeight;
      mirror.style.fontStretch = style.fontStretch;
      mirror.style.fontVariant = style.fontVariant;
      mirror.style.lineHeight = style.lineHeight;
      mirror.style.letterSpacing = style.letterSpacing;
      mirror.style.wordSpacing = style.wordSpacing;
      mirror.style.fontKerning = style.fontKerning;
      mirror.style.fontFeatureSettings = style.fontFeatureSettings;
      mirror.style.fontVariationSettings = style.fontVariationSettings;
      mirror.style.textTransform = style.textTransform;
      const paddingStart = Number.parseFloat(style.paddingInlineStart || style.paddingLeft) || 0;
      const left = Math.max(paddingStart, mirror.getBoundingClientRect().width + paddingStart - input.scrollLeft);
      setCaret((current) => current.left === left && current.visible && current.motion === motion
        ? current
        : { left, visible: true, motion });
    };
    useLayoutEffect(() => { updateCaret(caretMotion.current); });
    const nativeFallback = !caret.visible;
    return (
      <span className={`animated-caret-input ${nativeFallback ? 'animated-caret-native' : ''}`}>
        <input
          ref={setRefs}
          type={type}
          className={`text-input ${className}`}
          onFocus={(event) => { caretMotion.current = false; updateCaret(false); onFocus?.(event); }}
          onBlur={(event) => { setCaret((current) => ({ ...current, visible: false })); onBlur?.(event); }}
          onPointerDown={(event) => { caretMotion.current = false; onPointerDown?.(event); }}
          onSelect={(event) => { updateCaret(caretMotion.current); onSelect?.(event); }}
          onInput={(event) => { caretMotion.current = !composing.current; updateCaret(caretMotion.current); onInput?.(event); }}
          onScroll={(event) => { updateCaret(caretMotion.current); onScroll?.(event); }}
          onCompositionStart={(event) => { composing.current = true; caretMotion.current = false; setCaret((current) => ({ ...current, visible: false, motion: false })); onCompositionStart?.(event); }}
          onCompositionEnd={(event) => { composing.current = false; caretMotion.current = false; updateCaret(false); onCompositionEnd?.(event); }}
          onKeyDown={(event) => {
            onKeyDown?.(event);
            const navigation = !event.defaultPrevented && ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key);
            caretMotion.current = navigation;
            setCaret((current) => current.motion === navigation ? current : { ...current, motion: navigation });
            queueMicrotask(() => updateCaret(navigation));
          }}
          onKeyUp={(event) => { caretMotion.current = false; onKeyUp?.(event); }}
          {...props}
        />
        <span ref={mirrorRef} className="animated-caret-mirror" aria-hidden="true" />
        {caret.visible ? <span className={`animated-caret ${caret.motion ? 'animated-caret-motion' : ''}`} aria-hidden="true" style={{ transform: `translateX(${caret.left}px)` }}>|</span> : null}
      </span>
    );
  },
);

export function StatusPill({ status, tableCell = false }: { status: string; tableCell?: boolean }) {
  const normalized = status.toLowerCase().replaceAll('_', '-');
  return <span className={`status-pill status-${normalized}`} role={tableCell ? 'cell' : undefined}><i />{statusLabel(status)}</span>;
}

export function PageHeader({ eyebrow, title, description, action, backTo }: { eyebrow: string; title: string; description?: string; action?: ReactNode; backTo?: string }) {
  return (
    <header className="page-header">
      <div className="page-title-group">
        {backTo ? <NavLink className="back-link" to={backTo}><ArrowLeft size={16} /> 이전 화면</NavLink> : null}
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {description ? <p className="page-description">{description}</p> : null}
      </div>
      {action ? <div className="page-actions">{action}</div> : null}
    </header>
  );
}

const navigation = [
  { to: '/projects', label: '프로젝트', icon: FolderKanban },
];

export function AppShell({ user, onLogout, children }: { user: AuthenticatedUser; onLogout: () => void; children: ReactNode }) {
  const location = useLocation();
  const navigationItems = user.role === 'ADMIN'
    ? [...navigation, { to: '/users', label: '사용자 관리', icon: UserRound }]
    : navigation;
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <NavLink className="brand" to="/projects" aria-label="TOY SAST 홈">
          <span className="brand-symbol"><ShieldCheck size={21} /></span>
          <span><strong>TOY SAST</strong><small>Application Security</small></span>
        </NavLink>
        <nav className="sidebar-nav" aria-label="주요 메뉴">
          <p>WORKSPACE</p>
          {navigationItems.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} className={({ isActive }) => isActive || location.pathname.startsWith(to) ? 'active' : ''}>
              <Icon size={18} /><span>{label}</span><ChevronRight size={15} className="nav-arrow" />
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="account-summary">
            <span className="avatar"><UserRound size={17} /></span>
            <span><strong>{user.role === 'ADMIN' ? '시스템 관리자' : '일반 사용자'}</strong><small>{user.email}</small></span>
          </div>
          <button className="logout-button" type="button" onClick={onLogout}><LogOut size={16} /> 로그아웃</button>
        </div>
      </aside>
      <main className="main-content">{children}</main>
    </div>
  );
}

export function FilterInput({ value, onChange, placeholder, describedBy, invalid = false }: { value: string; onChange: (value: string) => void; placeholder: string; describedBy?: string; invalid?: boolean }) {
  return <label className="filter-input"><Search size={17} /><TextInput value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} aria-label={placeholder} aria-describedby={describedBy} aria-invalid={invalid || undefined} /></label>;
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return <div className="empty-state"><SlidersHorizontal size={25} /><strong>{title}</strong><p>{description}</p></div>;
}

export function ErrorPanel({ message }: { message: string }) {
  return <div className="error-panel" role="alert"><AlertTriangle size={20} /><div><strong>요청을 완료하지 못했습니다.</strong><p>{message}</p></div></div>;
}

export function AnalysisOverlay({ percent, status, exiting = false, onTransitionEnd }: { percent: number | null; status: ScanStatus; exiting?: boolean; onTransitionEnd?: () => void }) {
  const progress = percent == null ? '진행률 계산 중' : `${percent}%`;
  return (
    <div className={`analysis-overlay ${exiting ? 'analysis-overlay-complete' : ''}`} role="status" aria-live="polite" aria-atomic="true" aria-label={`${progress}, 보안 규칙 검사 중`} aria-busy={status !== 'COMPLETED'} onTransitionEnd={(event) => { if (event.propertyName === 'opacity') onTransitionEnd?.(); }}>
      <div className="analysis-overlay-content">
        <strong className="analysis-percent">{progress}</strong>
        <div className="split-dot-loader" aria-hidden="true" />
        <strong className="analysis-phase">보안 규칙 검사 중</strong>
        <p><span>Java · JavaScript · Python 규칙을 </span><br /><span>순차적으로 검사합니다.</span></p>
      </div>
    </div>
  );
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    COMPLETED: '완료', RUNNING: '진행 중', PENDING: '대기 중', FAILED: '실패', NONE: '분석 전',
    DETECTED: '탐지됨', REVIEW_REQUIRED: '검토 필요', NOT_DETECTED: '탐지되지 않음', NOT_SUPPORTED: '자동 탐지 미지원', CHECK_FAILED: '검사 실패',
    SUPPORTED: '자동 탐지 지원',
    CRITICAL: '매우 높음', HIGH: '높음', ERROR: '높음', WARNING: '중간', INFO: '낮음', MEDIUM: '중간', LOW: '낮음',
  };
  return labels[status] ?? status;
}

export function FileSummary({ file }: { file: File }) {
  return <div className="file-summary"><FileArchive size={20} /><span><strong>{file.name}</strong><small>{(file.size / 1024 / 1024).toFixed(2)} MiB · ZIP</small></span></div>;
}
