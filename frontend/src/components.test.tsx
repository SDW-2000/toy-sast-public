// @ts-expect-error Vitest provides Node's built-in filesystem module; the browser tsconfig intentionally omits Node types.
import { readFileSync } from 'node:fs';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { AnalysisOverlay, StatusPill, TextInput } from './components';

const stylesheet = readFileSync('src/styles.css', 'utf8');

describe('AnalysisOverlay', () => {
  it('shows real progress in the agreed content order without a progress bar', () => {
    const { container } = render(
      <AnalysisOverlay percent={68} status="RUNNING" />,
    );

    const content = container.querySelector('.analysis-overlay-content');
    expect(Array.from(content?.children ?? []).map((child) => child.textContent)).toEqual([
      '68%',
      '',
      '보안 규칙 검사 중',
      'Java · JavaScript · Python 규칙을 순차적으로 검사합니다.',
    ]);
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('uses a non-fabricated message until the total work is known', () => {
    render(<AnalysisOverlay percent={null} status="RUNNING" />);
    expect(screen.getByText('진행률 계산 중')).toBeInTheDocument();
  });

  it('shows 100 percent before the completion overlay begins to fade', () => {
    const { container } = render(
      <AnalysisOverlay percent={100} status="COMPLETED" />,
    );
    expect(screen.getByText('100%')).toBeInTheDocument();
    expect(container.firstChild).not.toHaveClass('analysis-overlay-complete');
  });

  it('uses one concise atomic status announcement and hides the decorative loader', () => {
    const { container } = render(<AnalysisOverlay percent={68} status="RUNNING" />);

    const status = screen.getByRole('status');
    expect(status).toHaveAttribute('aria-live', 'polite');
    expect(status).toHaveAttribute('aria-atomic', 'true');
    expect(status).toHaveAttribute('aria-label', '68%, 보안 규칙 검사 중');
    expect(container.querySelector('.split-dot-loader')).toHaveAttribute('aria-hidden', 'true');
  });

  it('only completes the opacity exit transition', () => {
    const onTransitionEnd = vi.fn();
    const { container } = render(<AnalysisOverlay percent={100} status="COMPLETED" exiting onTransitionEnd={onTransitionEnd} />);
    const overlay = container.firstChild!;

    fireEvent.transitionEnd(overlay, { propertyName: 'transform' });
    expect(onTransitionEnd).not.toHaveBeenCalled();
    fireEvent.transitionEnd(overlay, { propertyName: 'opacity' });
    expect(onTransitionEnd).toHaveBeenCalledOnce();
  });
});

describe('TextInput', () => {
  it('keeps native input behavior while applying the shared field style', () => {
    render(<TextInput aria-label="검색" placeholder="입력" />);
    expect(screen.getByRole('textbox', { name: '검색' })).toHaveClass('text-input');
  });

  it('forwards the native ref and restores the native caret for selections and IME composition', () => {
    const ref = { current: null as HTMLInputElement | null };
    const { container } = render(<TextInput ref={ref} aria-label="비밀번호" type="password" defaultValue="secret" />);
    const input = screen.getByLabelText('비밀번호') as HTMLInputElement;
    expect(ref.current).toBe(input);
    input.focus();
    input.setSelectionRange(1, 4);
    fireEvent.select(input);
    expect(container.querySelector('.animated-caret')).not.toBeInTheDocument();
    fireEvent.compositionStart(input);
    expect(container.querySelector('.animated-caret-input')).toHaveClass('animated-caret-native');
    fireEvent.compositionEnd(input);
  });

  it('measures its custom caret with the computed typography of the actual input', () => {
    const { container } = render(
      <TextInput
        aria-label="필터"
        defaultValue="KISA"
        style={{
          fontFamily: 'monospace',
          fontSize: '13px',
          fontStyle: 'italic',
          fontWeight: 500,
          lineHeight: '18px',
          letterSpacing: '0.5px',
          wordSpacing: '1px',
        }}
      />,
    );
    const input = screen.getByRole('textbox', { name: '필터' });
    input.focus();
    fireEvent.select(input);

    const mirror = container.querySelector('.animated-caret-mirror') as HTMLElement;
    expect(mirror.style.fontFamily).toBe('monospace');
    expect(mirror.style.fontSize).toBe('13px');
    expect(mirror.style.fontStyle).toBe('italic');
    expect(mirror.style.fontWeight).toBe('500');
    expect(mirror.style.lineHeight).toBe('18px');
    expect(mirror.style.letterSpacing).toBe('0.5px');
    expect(mirror.style.wordSpacing).toBe('1px');
  });

  it.each([
    ['ArrowLeft', 1],
    ['ArrowRight', 3],
    ['Home', 0],
    ['End', 4],
  ])('keeps the brief caret transition for %s selection movement', async (key, selection) => {
    const { container } = render(<TextInput aria-label="검색" defaultValue="abcd" />);
    const input = screen.getByRole('textbox', { name: '검색' }) as HTMLInputElement;
    act(() => {
      input.focus();
      input.setSelectionRange(2, 2);
      fireEvent.select(input);
    });

    fireEvent.keyDown(input, { key });
    input.setSelectionRange(selection, selection);
    await act(async () => { await Promise.resolve(); });

    expect(container.querySelector('.animated-caret')).toHaveClass('animated-caret-motion');
    fireEvent.keyUp(input, { key });
  });

  it('animates ordinary collapsed-caret typing without replacing native input behavior', () => {
    const { container } = render(<TextInput aria-label="검색" defaultValue="abc" />);
    const input = screen.getByRole('textbox', { name: '검색' }) as HTMLInputElement;
    act(() => input.focus());

    fireEvent.input(input, { target: { value: 'abcd' } });

    expect(input).toHaveValue('abcd');
    expect(container.querySelector('.animated-caret')).toHaveClass('animated-caret-motion');
  });

  it('keeps IME composition native and restores the drawn caret without motion', () => {
    const { container } = render(<TextInput aria-label="검색" defaultValue="한" />);
    const input = screen.getByRole('textbox', { name: '검색' }) as HTMLInputElement;
    act(() => input.focus());

    fireEvent.compositionStart(input);
    fireEvent.input(input, { target: { value: '한글' } });
    expect(container.querySelector('.animated-caret')).not.toBeInTheDocument();
    expect(container.querySelector('.animated-caret-input')).toHaveClass('animated-caret-native');

    fireEvent.compositionEnd(input);
    expect(container.querySelector('.animated-caret')).not.toHaveClass('animated-caret-motion');
  });

  it('keeps reduced-motion caret changes instant', () => {
    expect(stylesheet).toMatch(
      /@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.animated-caret-motion \{ transition: none; \}/,
    );
  });
});

describe('StatusPill', () => {
  it('renders the v2 check-failed state with a localized warning style', () => {
    render(<StatusPill status="CHECK_FAILED" />);

    expect(screen.getByText('검사 실패')).toHaveClass(
      'status-check-failed',
    );
  });

  it.each([
    ['CRITICAL', '매우 높음', 'status-critical'],
    ['ERROR', '높음', 'status-error'],
    ['WARNING', '중간', 'status-warning'],
    ['INFO', '낮음', 'status-info'],
  ])('localizes the %s severity', (status, label, className) => {
    render(<StatusPill status={status} />);

    expect(screen.getByText(label)).toHaveClass(className);
  });
});
