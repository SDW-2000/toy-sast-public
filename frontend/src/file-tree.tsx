import { useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent, ReactNode } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  FileArchive,
  FileCode2,
  FileQuestion,
  Folder,
  FolderOpen,
} from 'lucide-react';
import type {
  FileManifestNode,
  FileManifestPage,
  FileSelection,
} from './domain';
import { scanService } from './services';

const FILE_PAGE_LIMIT = 100;
const ARCHIVE_ROOT_PATH = '__toy_sast_archive_root__';

type FileTreeProps = {
  scanId: string;
  archiveName?: string;
  selection: FileSelection | null;
  onSelectionChange: (selection: FileSelection) => void;
};

export function FileTree(props: FileTreeProps) {
  return <FileTreeForScan key={props.scanId} {...props} />;
}

function FileTreeForScan({ scanId, archiveName = '분석 대상.zip', selection, onSelectionChange }: FileTreeProps) {
  const treeRef = useRef<HTMLDivElement>(null);
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(() => new Set([ARCHIVE_ROOT_PATH]));
  const [focusedPath, setFocusedPath] = useState<string | null>(null);

  const rootQuery = useFileChildren(scanId, null);
  const rootPage = rootQuery.data?.pages[0];
  const rootNodes = flattenPages(rootQuery.data?.pages);
  const activeFocusedPath = focusedPath ?? ARCHIVE_ROOT_PATH;

  const toggleDirectory = (path: string, nextExpanded?: boolean) => {
    const shouldExpand = nextExpanded ?? !expandedPaths.has(path);
    setExpandedPaths((current) => {
      const next = new Set(current);
      if (shouldExpand) next.add(path);
      else next.delete(path);
      return next;
    });
    if (!shouldExpand) setFocusedPath(path);
  };

  const focusTreeItem = (focusKey: string) => {
    setFocusedPath(focusKey);
    findRenderedTreeItemByFocusKey(treeRef.current, focusKey)?.focus();
  };

  const onTreeKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (target.getAttribute('role') !== 'treeitem') return;
    const focusKey = treeItemFocusKey(target);
    if (!focusKey) return;
    const path = target.dataset.path;
    const items = renderedTreeItems(treeRef.current);
    const index = items.indexOf(target);
    const currentIsArchive = target.dataset.entryType === 'ARCHIVE';
    const currentIsDirectory = target.dataset.entryType === 'DIRECTORY';
    const currentIsExpandable = (currentIsDirectory || currentIsArchive) && target.dataset.hasChildren === 'true';
    const currentExpanded = target.getAttribute('aria-expanded') === 'true';
    let next: HTMLElement | undefined;

    switch (event.key) {
      case 'ArrowDown':
        next = items[index + 1];
        break;
      case 'ArrowUp':
        next = items[index - 1];
        break;
      case 'Home':
        next = items[0];
        break;
      case 'End':
        next = items.at(-1);
        break;
      case 'ArrowRight':
        if (path && currentIsExpandable && !currentExpanded) {
          toggleDirectory(path, true);
        } else if (currentIsExpandable) {
          next = items.find((item) => item !== target && item.dataset.parentPath === (currentIsArchive ? '' : path));
        }
        break;
      case 'ArrowLeft':
        if (path && (currentIsDirectory || currentIsArchive) && currentExpanded) {
          toggleDirectory(path, false);
        } else if (target.dataset.parentPath !== undefined) {
          next = target.dataset.parentPath
            ? findRenderedTreeItem(treeRef.current, target.dataset.parentPath)
            : findRenderedTreeItem(treeRef.current, ARCHIVE_ROOT_PATH);
        }
        break;
      case 'Enter':
      case ' ':
        if (!path) return;
        onSelectionChange(currentIsArchive
          ? { path: '', pathScope: 'ARCHIVE', archiveName }
          : { path, pathScope: currentIsDirectory ? 'DIRECTORY' : 'FILE' });
        break;
      default:
        return;
    }

    event.preventDefault();
    const nextFocusKey = next ? treeItemFocusKey(next) : undefined;
    if (nextFocusKey) focusTreeItem(nextFocusKey);
  };

  if (rootQuery.isPending) {
    return <FileTreePanel><div className="file-tree-message" role="status">파일 구조를 불러오는 중입니다.</div></FileTreePanel>;
  }
  if (rootQuery.isError) {
    return <FileTreePanel><div className="file-tree-message file-tree-error" role="alert">파일 구조를 불러오지 못했습니다.</div></FileTreePanel>;
  }
  if (!rootPage?.manifestAvailable) {
    return (
      <FileTreePanel>
        <div className="file-tree-message">
          <strong>파일 구조 기록이 없습니다.</strong>
          <span>{rootPage?.unavailableReason === 'LEGACY_SCAN' ? '이 분석은 파일 구조 저장 이전에 완료되었습니다.' : '저장된 파일 구조를 사용할 수 없습니다.'}</span>
        </div>
      </FileTreePanel>
    );
  }

  return (
    <FileTreePanel>
      <div
        ref={treeRef}
        className="file-tree"
        role="tree"
        aria-label="분석 파일 구조"
        aria-busy={rootQuery.isFetchingNextPage}
        onKeyDown={onTreeKeyDown}
      >
        <div
          className={`file-tree-item file-tree-archive-root ${selection?.pathScope === 'ARCHIVE' ? 'file-tree-item-selected' : ''}`}
          role="treeitem"
          aria-label={`${archiveName}, 전체 이슈`}
          aria-expanded={expandedPaths.has(ARCHIVE_ROOT_PATH)}
          aria-selected={selection?.pathScope === 'ARCHIVE'}
          aria-level={1}
          data-path={ARCHIVE_ROOT_PATH}
          data-parent-path=""
          data-entry-type="ARCHIVE"
          data-has-children={rootNodes.length > 0 || rootQuery.hasNextPage}
          tabIndex={activeFocusedPath === ARCHIVE_ROOT_PATH ? 0 : -1}
          onFocus={(event) => { if (event.target === event.currentTarget) setFocusedPath(ARCHIVE_ROOT_PATH); }}
          onClick={(event) => {
            if ((event.target as Element).closest('[role="treeitem"]') !== event.currentTarget) return;
            onSelectionChange({ path: '', pathScope: 'ARCHIVE', archiveName });
          }}
        >
          <div className="file-tree-row" style={{ paddingInlineStart: '10px' }}>
            <button
              type="button"
              className="file-tree-toggle"
              tabIndex={-1}
              aria-label={`${archiveName} ${expandedPaths.has(ARCHIVE_ROOT_PATH) ? '접기' : '펼치기'}`}
              onClick={(event) => {
                event.stopPropagation();
                toggleDirectory(ARCHIVE_ROOT_PATH);
                (event.currentTarget.closest('[role="treeitem"]') as HTMLElement | null)?.focus();
              }}
            >
              {expandedPaths.has(ARCHIVE_ROOT_PATH) ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
            <FileArchiveIcon />
            <span className="file-tree-name" title={archiveName}>{archiveName}</span>
          </div>
          {expandedPaths.has(ARCHIVE_ROOT_PATH) ? (
            <div role="group" aria-busy={rootQuery.isFetchingNextPage}>
              {rootNodes.map((node) => (
                <FileTreeNode
                  key={node.path}
                  node={node}
                  scanId={scanId}
                  selection={selection}
                  expandedPaths={expandedPaths}
                  focusedPath={activeFocusedPath}
                  onFocusPath={setFocusedPath}
                  onRequestFocus={focusTreeItem}
                  onSelect={onSelectionChange}
                  onToggle={toggleDirectory}
                  levelOffset={1}
                />
              ))}
              {rootQuery.hasNextPage ? (
                <TreeLoadMore
                  label="최상위 파일 더 보기"
                  level={2}
                  parentPath={null}
                  loading={rootQuery.isFetchingNextPage}
                  focused={activeFocusedPath === loadMoreFocusKey(null)}
                  onFocus={() => setFocusedPath(loadMoreFocusKey(null))}
                  onRequestFallbackFocus={() => {
                    const fallback = rootNodes.at(-1)?.path;
                    if (fallback) focusTreeItem(fallback);
                  }}
                  onLoad={() => void rootQuery.fetchNextPage()}
                />
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </FileTreePanel>
  );
}

function FileTreePanel({ children }: { children: ReactNode }) {
  return (
    <aside className="file-tree-panel" aria-label="파일 구조 패널">
      <div className="file-tree-heading">
        <strong>파일 구조</strong>
        <span>소스 내용은 저장하지 않습니다.</span>
      </div>
      {children}
    </aside>
  );
}

type FileTreeNodeProps = {
  node: FileManifestNode;
  scanId: string;
  selection: FileSelection | null;
  expandedPaths: Set<string>;
  focusedPath: string | null;
  onFocusPath: (path: string) => void;
  onRequestFocus: (path: string) => void;
  onSelect: (selection: FileSelection) => void;
  onToggle: (path: string, nextExpanded?: boolean) => void;
  levelOffset?: number;
};

function FileTreeNode(props: FileTreeNodeProps) {
  const {
    node,
    selection,
    expandedPaths,
    focusedPath,
    onFocusPath,
    onSelect,
    onToggle,
    levelOffset = 0,
  } = props;
  const isDirectory = node.entryType === 'DIRECTORY';
  const isExpandable = isDirectory && node.hasChildren;
  const isExpanded = isExpandable && expandedPaths.has(node.path);
  const isSelected = selection?.path === node.path && selection.pathScope === (isDirectory ? 'DIRECTORY' : 'FILE');

  return (
    <div
      className={`file-tree-item ${isSelected ? 'file-tree-item-selected' : ''}`}
      role="treeitem"
      aria-label={fileTreeNodeLabel(node)}
      aria-expanded={isExpandable ? isExpanded : undefined}
      aria-selected={isSelected}
      aria-level={node.depth + levelOffset}
      data-path={node.path}
      data-parent-path={node.parentPath ?? ''}
      data-entry-type={node.entryType}
      data-has-children={node.hasChildren}
      tabIndex={focusedPath === node.path ? 0 : -1}
      onFocus={(event) => { if (event.target === event.currentTarget) onFocusPath(node.path); }}
      onClick={(event) => {
        if ((event.target as Element).closest('[role="treeitem"]') !== event.currentTarget) return;
        onSelect({ path: node.path, pathScope: isDirectory ? 'DIRECTORY' : 'FILE' });
      }}
    >
      <div
        className="file-tree-row"
        style={{ paddingInlineStart: `${10 + Math.max(0, node.depth - 1 + levelOffset) * 16}px` } as CSSProperties}
      >
        {isExpandable ? (
          <button
            type="button"
            className="file-tree-toggle"
            tabIndex={-1}
            aria-label={`${node.name} ${isExpanded ? '접기' : '펼치기'}`}
            onClick={(event) => {
              event.stopPropagation();
              onToggle(node.path);
              (event.currentTarget.closest('[role="treeitem"]') as HTMLElement | null)?.focus();
            }}
          >
            {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        ) : <span className="file-tree-toggle" aria-hidden="true" />}
        <FileTreeIcon node={node} expanded={isExpanded} />
        <span className="file-tree-name" title={node.path}>{node.name}</span>
        {node.findingCount > 0 ? <span className="file-tree-count" aria-label={`이슈 ${node.findingCount}개`}>{node.findingCount}</span> : null}
        <AnalysisStateLabel node={node} />
      </div>
      {isExpanded ? (
        <FileTreeChildren {...props} parentPath={node.path} />
      ) : null}
    </div>
  );
}

function FileTreeChildren(props: FileTreeNodeProps & { parentPath: string }) {
  const { scanId, parentPath } = props;
  const query = useFileChildren(scanId, parentPath);
  const nodes = flattenPages(query.data?.pages);

  return (
    <>
      {query.isPending ? <div className="file-tree-inline-message" role="status">불러오는 중…</div> : null}
      {query.isError ? <div className="file-tree-inline-message file-tree-error" role="alert">하위 구조를 불러오지 못했습니다.</div> : null}
      <div role="group" aria-busy={query.isPending || query.isFetchingNextPage}>
        {nodes.map((node) => <FileTreeNode key={node.path} {...props} node={node} />)}
        {query.hasNextPage ? (
          <TreeLoadMore
            label={`${parentPath} 더 보기`}
            level={props.node.depth + 1}
            parentPath={parentPath}
            loading={query.isFetchingNextPage}
            focused={props.focusedPath === loadMoreFocusKey(parentPath)}
            onFocus={() => props.onFocusPath(loadMoreFocusKey(parentPath))}
            onRequestFallbackFocus={() => props.onRequestFocus(parentPath)}
            onLoad={() => void query.fetchNextPage()}
          />
        ) : null}
      </div>
    </>
  );
}

function TreeLoadMore({
  label,
  level,
  parentPath,
  loading,
  focused,
  onFocus,
  onRequestFallbackFocus,
  onLoad,
}: {
  label: string;
  level: number;
  parentPath: string | null;
  loading: boolean;
  focused: boolean;
  onFocus: () => void;
  onRequestFallbackFocus: () => void;
  onLoad: () => void;
}) {
  const activate = () => {
    if (loading) return;
    onRequestFallbackFocus();
    onLoad();
  };
  return (
    <div
      className="file-tree-more"
      role="treeitem"
      aria-label={label}
      aria-level={level}
      aria-disabled={loading}
      data-focus-key={loadMoreFocusKey(parentPath)}
      data-parent-path={parentPath ?? ''}
      tabIndex={focused ? 0 : -1}
      onFocus={onFocus}
      onClick={activate}
      onKeyDown={(event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        event.stopPropagation();
        activate();
      }}
    >
      {loading ? '불러오는 중…' : '더 보기'}
    </div>
  );
}

function FileTreeIcon({ node, expanded }: { node: FileManifestNode; expanded: boolean }) {
  if (node.entryType === 'DIRECTORY') return expanded ? <FolderOpen size={15} /> : <Folder size={15} />;
  return node.analysisState === 'UNSUPPORTED_EXTENSION' ? <FileQuestion size={15} /> : <FileCode2 size={15} />;
}

function FileArchiveIcon() {
  return <FileArchive size={15} aria-hidden="true" />;
}

function AnalysisStateLabel({ node }: { node: FileManifestNode }) {
  const labels: Partial<Record<FileManifestNode['analysisState'], string>> = {
    EXCLUDED_DIRECTORY: '제외',
    UNSUPPORTED_EXTENSION: '미지원',
  };
  const label = labels[node.analysisState];
  return label ? <span className={`file-tree-state state-${node.analysisState.toLowerCase().replace('_', '-')}`}>{label}</span> : null;
}

function fileTreeNodeLabel(node: FileManifestNode) {
  const state = node.analysisState === 'EXCLUDED_DIRECTORY'
    ? '제외'
    : node.analysisState === 'UNSUPPORTED_EXTENSION'
      ? '미지원'
      : null;
  return [node.name, node.findingCount ? `이슈 ${node.findingCount}개` : null, state]
    .filter(Boolean)
    .join(', ');
}

function useFileChildren(scanId: string, parentPath: string | null) {
  return useInfiniteQuery({
    queryKey: ['scan-file-children', scanId, parentPath],
    queryFn: ({ pageParam }) => scanService.files(scanId, {
      parentPath: parentPath ?? undefined,
      limit: FILE_PAGE_LIMIT,
      cursor: pageParam ?? undefined,
    }),
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    staleTime: Number.POSITIVE_INFINITY,
  });
}

function flattenPages(pages: FileManifestPage[] | undefined): FileManifestNode[] {
  if (!pages) return [];
  const seen = new Set<string>();
  return pages.flatMap((page) => page.items.filter((item) => {
    if (seen.has(item.path)) return false;
    seen.add(item.path);
    return true;
  }));
}

function renderedTreeItems(root: HTMLDivElement | null): HTMLElement[] {
  return root ? Array.from(root.querySelectorAll<HTMLElement>('[role="treeitem"][data-path], [role="treeitem"][data-focus-key]')) : [];
}

function findRenderedTreeItem(root: HTMLDivElement | null, path: string): HTMLElement | undefined {
  return renderedTreeItems(root).find((item) => item.dataset.path === path);
}

function findRenderedTreeItemByFocusKey(root: HTMLDivElement | null, focusKey: string): HTMLElement | undefined {
  return renderedTreeItems(root).find((item) => treeItemFocusKey(item) === focusKey);
}

function treeItemFocusKey(item: HTMLElement): string | undefined {
  return item.dataset.focusKey ?? item.dataset.path;
}

function loadMoreFocusKey(parentPath: string | null): string {
  return `../__toy_sast_load_more__/${parentPath ?? 'root'}`;
}
