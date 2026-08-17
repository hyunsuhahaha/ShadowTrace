import { useState } from "react";

// Shared with GraphCanvas.tsx's drop handler, so anything dragged out of a
// list -- this tree, a zip's own member listing, an ftp session's download
// log -- and a graph waiting to accept a drop agree on what payload to
// expect. `kind` picks which promote endpoint GraphWorkspace's dropFile
// calls; the rest of each variant is that endpoint's own request shape.
export const FILE_DRAG_MIME = "application/x-oscp-tree-file";
export type FileDragPayload =
  | { kind: "post-exploitation"; runId: number; path: string }
  | { kind: "autorecon-result"; jobId: number; path: string; graphNodeId: string | null }
  | { kind: "archive"; evidenceId: number; entry: string }
  | { kind: "ftp-download"; sessionId: number; filename: string; graphNodeId: string | null }
  | { kind: "ftp-tree"; executionId: number; path: string; graphNodeId: string | null };

// Shared by every "show a remote host's directory structure automatically"
// feature (post-exploitation file listings, SMB share spidering, NFS
// exports, ...) so each one only has to turn its own protocol-specific
// output into {path, isDir}[] and hand it here.
export type TreeNode = {
  name: string; path: string; isDir: boolean; children: Map<string, TreeNode>;
};

export function buildFileTree(entries: { path: string; isDir: boolean }[], sep: string): TreeNode {
  const root: TreeNode = { name: "", path: "", isDir: true, children: new Map() };
  for (const entry of entries) {
    // A leading separator ("/home/bob") reconstructs with one back; a drive
    // letter ("C:\Users") has no leading separator to restore -- filter()
    // below strips it either way, so this is the only place that knows
    // whether the root itself needs one put back.
    const rootNeedsSep = entry.path.startsWith(sep);
    const parts = entry.path.split(sep).filter(Boolean);
    let node = root;
    parts.forEach((part, i) => {
      const isLast = i === parts.length - 1;
      let child = node.children.get(part);
      if (!child) {
        const path = node === root
          ? (rootNeedsSep ? sep + part : part)
          : `${node.path}${sep}${part}`;
        child = { name: part, path, isDir: !isLast || entry.isDir, children: new Map() };
        node.children.set(part, child);
      }
      node = child;
    });
  }
  return root;
}

// Keeps a folder if its own name matches, or if any descendant does (with
// that descendant's own ancestor chain filtered the same way); a matching
// folder keeps its whole subtree untouched below it rather than filtering
// further, since finding "Desktop" should show everything on it.
export function filterTree(node: TreeNode, query: string): TreeNode {
  const q = query.trim().toLowerCase();
  if (!q) return node;
  const children = new Map<string, TreeNode>();
  for (const [key, child] of node.children) {
    if (child.name.toLowerCase().includes(q)) {
      children.set(key, child);
    } else if (child.isDir) {
      const filtered = filterTree(child, q);
      if (filtered.children.size) children.set(key, filtered);
    }
  }
  return { ...node, children };
}

// Lines tagged "D|<path>" / "F|<path>" (used by the linux/windows post-
// exploitation file-tree commands and the NFS export walker) parsed into
// the {path, isDir}[] shape buildFileTree expects.
export function parseTaggedTreeLines(output: string): { path: string; isDir: boolean }[] {
  const entries: { path: string; isDir: boolean }[] = [];
  for (const line of output.split("\n")) {
    const m = /^([DF])\|(.+)$/.exec(line.trim());
    if (m) entries.push({ path: m[2], isDir: m[1] === "D" });
  }
  return entries;
}

function FolderIcon() {
  return (
    <svg className="fileTreeFolderIcon" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
      <path
        fill="#dab164"
        d="M1.5 3.5A1.5 1.5 0 0 1 3 2h3.4a1.5 1.5 0 0 1 1.06.44l.94.94A1.5 1.5 0 0 0 9.46 4H13a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 13 14H3a1.5 1.5 0 0 1-1.5-1.5v-9Z"
      />
    </svg>
  );
}

function FileIcon() {
  return (
    <svg className="fileTreeFileIcon" width="12" height="12" viewBox="0 0 16 16" aria-hidden="true">
      <path fill="none" stroke="#7c8f93" strokeWidth="1.1" d="M3.5 1.5h6l3 3v10a1 1 0 0 1-1 1h-8a1 1 0 0 1-1-1v-12a1 1 0 0 1 1-1Z" />
      <path fill="none" stroke="#7c8f93" strokeWidth="1.1" d="M9.5 1.5v3h3" />
    </svg>
  );
}

// depth 0 is the scrollable root box (.fileTree); every nested level renders
// .fileTreeChildren instead so indentation compounds per level rather than
// every recursive call re-applying the root's own height/overflow/padding.
//
// `searchable` only has an effect at depth 0 -- it owns the query input and
// filters `node` before the first render, so every recursive call below
// just walks the already-filtered subtree. A query also force-opens every
// <details> on the way down, since a match three folders deep is useless
// hidden behind three collapsed twisties.
export function FileTreeView({ node, depth = 0, searchable, onOpenFile, runId, dragPayload, query = "" }: {
  node: TreeNode; depth?: number; searchable?: boolean;
  onOpenFile?: (path: string) => void; runId?: number;
  // Generic drag-to-graph source for any tree, not just post-exploitation's
  // runId-keyed one -- pass a factory turning a clicked path into whatever
  // FileDragPayload variant that tree's own promote endpoint expects.
  dragPayload?: (path: string) => FileDragPayload; query?: string;
}) {
  const [ownQuery, setOwnQuery] = useState("");
  const activeQuery = depth === 0 && searchable ? ownQuery : query;
  const displayNode = activeQuery ? filterTree(node, activeQuery) : node;
  const entries = [...displayNode.children.values()].sort((a, b) =>
    a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1);
  const dragFor = dragPayload ?? (runId != null
    ? (path: string): FileDragPayload => ({ kind: "post-exploitation", runId, path })
    : undefined);
  return (<>
    {depth === 0 && searchable && (
      <input className="fileTreeSearch" type="search" value={ownQuery}
        onChange={(event) => setOwnQuery(event.target.value)}
        placeholder="이름으로 검색…" aria-label="파일 트리 검색" />
    )}
    {!!entries.length && (
      <ul className={depth === 0 ? "fileTree" : "fileTreeChildren"}>
        {entries.map((child) => (
          <li key={child.name}>
            {child.isDir ? (
              <details open={!!activeQuery}>
                <summary>
                  <span className="fileTreeChevron" />
                  <FolderIcon />
                  {child.name}
                </summary>
                <FileTreeView node={child} depth={depth + 1}
                  onOpenFile={onOpenFile} runId={runId} dragPayload={dragPayload} query={activeQuery} />
              </details>
            ) : onOpenFile ? (
              <button type="button" className="fileTreeFile fileTreeFile--clickable"
                draggable={dragFor != null}
                onDragStart={dragFor == null ? undefined : (event) => {
                  event.dataTransfer.setData(FILE_DRAG_MIME, JSON.stringify(dragFor(child.path)));
                  event.dataTransfer.effectAllowed = "copy";
                }}
                onClick={() => onOpenFile(child.path)}>
                <FileIcon />
                {child.name}
              </button>
            ) : (
              <span className="fileTreeFile">
                <FileIcon />
                {child.name}
              </span>
            )}
          </li>
        ))}
      </ul>
    )}
  </>);
}
