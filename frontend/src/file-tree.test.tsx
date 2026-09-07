import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type {
  FileManifestNode,
  FileManifestPage,
  FileSelection,
} from './domain';
import { FileTree } from './file-tree';

const scanId = '33333333-3333-4333-8333-333333333333';

const rootNodes: FileManifestNode[] = [
  node('src', null, 'DIRECTORY', 'DIRECTORY', true, 1, 1),
  node('vendor', null, 'DIRECTORY', 'EXCLUDED_DIRECTORY', false, 1),
  node('README.md', null, 'FILE', 'UNSUPPORTED_EXTENSION', false, 1),
];

const srcNodes: FileManifestNode[] = [
  node('src/api', 'src', 'DIRECTORY', 'DIRECTORY', true, 2),
  node('src/App.tsx', 'src', 'FILE', 'TARGET', false, 2, 2, 'JavaScript'),
];

function node(
  path: string,
  parentPath: string | null,
  entryType: FileManifestNode['entryType'],
  analysisState: FileManifestNode['analysisState'],
  hasChildren: boolean,
  depth: number,
  findingCount = 0,
  language: string | null = null,
): FileManifestNode {
  return {
    path,
    parentPath,
    name: path.split('/').at(-1)!,
    depth,
    entryType,
    sizeBytes: entryType === 'FILE' ? 128 : null,
    language,
    analysisState,
    findingCount,
    hasChildren,
  };
}

function page(
  parentPath: string | null,
  items: FileManifestNode[],
  options: Partial<FileManifestPage> = {},
): FileManifestPage {
  return {
    scanId,
    manifestAvailable: true,
    manifestVersion: 1,
    unavailableReason: null,
    parentPath,
    items,
    nextCursor: null,
    ...options,
  };
}

function json(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'Content-Type': 'application/json' } });
}

function installManifestMock(
  handler?: (url: URL) => FileManifestPage | Response | undefined,
) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = new URL(String(input));
    const handled = handler?.(url);
    if (handled instanceof Response) return handled;
    if (handled) return json(handled);
    const parentPath = url.searchParams.get('parentPath');
    if (parentPath === 'src') return json(page('src', srcNodes));
    if (parentPath === 'src/api') return json(page('src/api', [
      node('src/api/client.ts', 'src/api', 'FILE', 'TARGET', false, 3, 1, 'JavaScript'),
    ]));
    return json(page(null, rootNodes));
  });
}

function FileTreeHarness({
  activeScanId = scanId,
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } }),
}: {
  activeScanId?: string;
  client?: QueryClient;
}) {
  const [selection, setSelection] = useState<FileSelection | null>(null);
  return (
    <QueryClientProvider client={client}>
      <FileTree scanId={activeScanId} selection={selection} onSelectionChange={setSelection} />
      <output>{selection ? `${selection.pathScope}:${selection.path}` : 'NONE'}</output>
    </QueryClientProvider>
  );
}

describe('FileTree', () => {
  afterEach(() => vi.restoreAllMocks());

  it('requests only the root at first and uses the parent-scoped query key', async () => {
    const fetchMock = installManifestMock();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<FileTreeHarness client={client} />);

    expect(await screen.findByRole('treeitem', { name: /src/ })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const rootUrl = new URL(String(fetchMock.mock.calls[0][0]));
    expect(rootUrl.pathname).toBe(`/api/scans/${scanId}/files`);
    expect(rootUrl.searchParams.get('parentPath')).toBeNull();
    expect(rootUrl.searchParams.get('limit')).toBe('100');
    expect(client.getQueryData(['scan-file-children', scanId, null])).toBeDefined();
    expect(screen.queryByText('App.tsx')).not.toBeInTheDocument();
  });

  it('loads children on expansion, removes them on collapse, and reuses the cached directory query', async () => {
    const fetchMock = installManifestMock();
    const user = userEvent.setup();
    render(<FileTreeHarness />);
    const src = await screen.findByRole('treeitem', { name: /src/ });

    act(() => src.focus());
    await user.keyboard('{ArrowRight}');
    expect(await screen.findByRole('treeitem', { name: /App\.tsx/ })).toBeInTheDocument();
    expect(src).toHaveAttribute('aria-expanded', 'true');

    await user.keyboard('{ArrowLeft}');
    expect(screen.queryByRole('treeitem', { name: /App\.tsx/ })).not.toBeInTheDocument();
    expect(src).toHaveAttribute('aria-expanded', 'false');

    await user.keyboard('{ArrowRight}');
    expect(await screen.findByRole('treeitem', { name: /App\.tsx/ })).toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([input]) => new URL(String(input)).searchParams.get('parentPath') === 'src')).toHaveLength(1);
  });

  it('loads a directory cursor page without rendering duplicate paths', async () => {
    const fetchMock = installManifestMock((url) => {
      if (url.searchParams.get('parentPath') !== 'src') return undefined;
      if (url.searchParams.get('cursor') === 'src-next') {
        return page('src', [
          srcNodes[1],
          node('src/utils.ts', 'src', 'FILE', 'TARGET', false, 2, 0, 'JavaScript'),
        ]);
      }
      return page('src', srcNodes, { nextCursor: 'src-next' });
    });
    const user = userEvent.setup();
    render(<FileTreeHarness />);
    const src = await screen.findByRole('treeitem', { name: /src/ });
    act(() => src.focus());
    await user.keyboard('{ArrowRight}');

    const loadMore = await screen.findByRole('treeitem', { name: 'src 더 보기' });
    expect(loadMore.parentElement).toHaveAttribute('role', 'group');
    expect(loadMore).toHaveAttribute('aria-level', '2');
    act(() => loadMore.focus());
    await user.keyboard('{Enter}');
    expect(src).toHaveFocus();
    expect(await screen.findByRole('treeitem', { name: /utils\.ts/ })).toBeInTheDocument();
    expect(screen.getAllByRole('treeitem', { name: /App\.tsx/ })).toHaveLength(1);
    expect(fetchMock.mock.calls.some(([input]) => {
      const url = new URL(String(input));
      return url.searchParams.get('parentPath') === 'src'
        && url.searchParams.get('cursor') === 'src-next';
    })).toBe(true);
  });

  it('implements roving focus, tree ARIA, expansion, parent navigation, and selection keys', async () => {
    installManifestMock();
    const user = userEvent.setup();
    render(<FileTreeHarness />);
    const tree = await screen.findByRole('tree', { name: '분석 파일 구조' });
    const src = screen.getByRole('treeitem', { name: /src/ });
    const vendor = screen.getByRole('treeitem', { name: /vendor/ });
    expect(tree).toBeInTheDocument();
    expect(src).toHaveAttribute('aria-level', '2');
    expect(src).toHaveAttribute('tabindex', '-1');
    expect(vendor).toHaveAttribute('tabindex', '-1');

    act(() => src.focus());
    await user.keyboard('{ArrowDown}');
    expect(vendor).toHaveFocus();
    await user.keyboard('{Home}');
    expect(screen.getByRole('treeitem', { name: /분석 대상\.zip/ })).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    expect(src).toHaveFocus();
    await user.keyboard('{ArrowRight}');
    const api = await screen.findByRole('treeitem', { name: /api/ });
    expect(api).toHaveAttribute('aria-level', '3');
    expect(api.parentElement).toHaveAttribute('role', 'group');
    expect(api.parentElement?.parentElement).toBe(src);
    expect(src).toHaveAttribute('aria-expanded', 'true');
    await user.keyboard('{ArrowRight}');
    expect(api).toHaveFocus();
    await user.keyboard('{ArrowLeft}');
    expect(src).toHaveFocus();
    await user.keyboard(' ');
    expect(src).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('DIRECTORY:src')).toBeInTheDocument();
  });

  it('labels mixed manifest findings as issues in visible and accessible text', async () => {
    installManifestMock();
    render(<FileTreeHarness />);

    const src = await screen.findByRole('treeitem', { name: 'src, 이슈 1개' });
    expect(src).toBeInTheDocument();
    expect(screen.getByLabelText('이슈 1개')).toHaveTextContent('1');
  });

  it('renders the archive virtual root and keeps expansion separate from selection', async () => {
    installManifestMock();
    const user = userEvent.setup();
    render(<FileTreeHarness />);

    const archive = await screen.findByRole('treeitem', { name: /분석 대상\.zip/ });
    expect(archive).toHaveAttribute('aria-level', '1');
    expect(screen.getByRole('treeitem', { name: /src/ })).toHaveAttribute('aria-level', '2');
    await user.click(screen.getByRole('button', { name: /분석 대상\.zip 접기/ }));
    expect(screen.getByRole('treeitem', { name: /분석 대상\.zip/ })).toHaveAttribute('aria-selected', 'false');
    expect(screen.queryByRole('treeitem', { name: /src/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /분석 대상\.zip 펼치기/ }));
    await user.click(screen.getByRole('treeitem', { name: /분석 대상\.zip/ }));
    expect(screen.getByText('ARCHIVE:')).toBeInTheDocument();
  });

  it('resets expansion and roving focus for a new scan while keeping exactly one root tab stop', async () => {
    installManifestMock();
    const user = userEvent.setup();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const secondScanId = '55555555-5555-4555-8555-555555555555';
    const view = render(<FileTreeHarness activeScanId={scanId} client={client} />);

    await screen.findByRole('treeitem', { name: /src/ });
    const toggle = screen.getByRole('button', { name: 'src 펼치기' });
    expect(toggle).toHaveAttribute('tabindex', '-1');
    await user.click(toggle);
    expect(await screen.findByRole('treeitem', { name: /App\.tsx/ })).toBeInTheDocument();
    expect(screen.getByRole('treeitem', { name: /src/ })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('treeitem', { name: /api/ })).toHaveFocus();
    const appFile = screen.getByRole('treeitem', { name: /App\.tsx/ });
    act(() => appFile.focus());
    expect(appFile).toHaveAttribute('tabindex', '0');

    view.rerender(<FileTreeHarness activeScanId={secondScanId} client={client} />);

    const resetSrc = await screen.findByRole('treeitem', { name: /src/ });
    expect(resetSrc).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('treeitem', { name: /App\.tsx/ })).not.toBeInTheDocument();
    expect(screen.getAllByRole('treeitem').filter((item) => item.getAttribute('tabindex') === '0')).toHaveLength(1);
    expect(screen.getByRole('treeitem', { name: /분석 대상\.zip/ })).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('button', { name: 'src 펼치기' })).toBeInTheDocument();

    view.rerender(<FileTreeHarness activeScanId={scanId} client={client} />);

    const roundTripSrc = await screen.findByRole('treeitem', { name: /src/ });
    expect(roundTripSrc).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('treeitem', { name: /App\.tsx/ })).not.toBeInTheDocument();
    expect(screen.getByRole('treeitem', { name: /분석 대상\.zip/ })).toHaveAttribute('tabindex', '0');
  });

  it('shows a stable legacy empty state and labels excluded and unsupported entries', async () => {
    installManifestMock((url) => {
      if (url.searchParams.has('parentPath')) return undefined;
      return page(null, [], {
        manifestAvailable: false,
        manifestVersion: null,
        unavailableReason: 'LEGACY_SCAN',
      });
    });
    const { unmount } = render(<FileTreeHarness />);
    expect(await screen.findByText('파일 구조 기록이 없습니다.')).toBeInTheDocument();
    expect(screen.getByText('이 분석은 파일 구조 저장 이전에 완료되었습니다.')).toBeInTheDocument();

    unmount();
    vi.restoreAllMocks();
    installManifestMock();
    render(<FileTreeHarness />);
    expect(await screen.findByText('제외')).toBeInTheDocument();
    expect(screen.getByText('미지원')).toBeInTheDocument();
  });

  it('announces root loading and root or child request failures without exposing source content', async () => {
    let resolveRoot!: (response: Response) => void;
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<Response>((resolve) => {
      resolveRoot = resolve;
    }));
    const loadingView = render(<FileTreeHarness />);

    expect(screen.getByText('파일 구조를 불러오는 중입니다.')).toHaveAttribute('role', 'status');
    await act(async () => resolveRoot(json(page(null, rootNodes))));
    expect(await screen.findByRole('tree', { name: '분석 파일 구조' })).toBeInTheDocument();
    expect(screen.getByText('소스 내용은 저장하지 않습니다.')).toBeInTheDocument();

    loadingView.unmount();
    vi.restoreAllMocks();
    installManifestMock(() => json({ detail: 'manifest unavailable' }, 500));
    const rootErrorView = render(<FileTreeHarness />);
    expect(await screen.findByRole('alert')).toHaveTextContent('파일 구조를 불러오지 못했습니다.');

    rootErrorView.unmount();
    vi.restoreAllMocks();
    installManifestMock((url) => (
      url.searchParams.get('parentPath') === 'src'
        ? json({ detail: 'child unavailable' }, 500)
        : undefined
    ));
    const user = userEvent.setup();
    render(<FileTreeHarness />);
    const src = await screen.findByRole('treeitem', { name: /src/ });
    act(() => src.focus());
    await user.keyboard('{ArrowRight}');
    expect(await screen.findByRole('alert')).toHaveTextContent('하위 구조를 불러오지 못했습니다.');
  });

  it('keeps a collapsed large directory out of the DOM and does not request its children', async () => {
    const huge = node('huge', null, 'DIRECTORY', 'DIRECTORY', true, 1);
    const fetchMock = installManifestMock((url) => {
      if (!url.searchParams.has('parentPath')) return page(null, [huge]);
      if (url.searchParams.get('parentPath') === 'huge') {
        return page('huge', Array.from({ length: 1000 }, (_, index) => (
          node(`huge/file-${index}.js`, 'huge', 'FILE', 'TARGET', false, 2, 0, 'JavaScript')
        )));
      }
      return undefined;
    });
    render(<FileTreeHarness />);

    expect(await screen.findByRole('treeitem', { name: /huge/ })).toBeInTheDocument();
    expect(screen.getAllByRole('treeitem')).toHaveLength(2);
    expect(screen.queryByText('file-999.js')).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input]) => new URL(String(input)).searchParams.get('parentPath') === 'huge')).toBe(false);
  });
});
