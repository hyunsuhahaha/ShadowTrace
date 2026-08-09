// Shared by every "show a remote host's directory structure automatically"
// feature (post-exploitation file listings, SMB share spidering, NFS
// exports, ...) so each one only has to turn its own protocol-specific
// output into {path, isDir}[] and hand it here.
export type TreeNode = { name: string; isDir: boolean; children: Map<string, TreeNode> };

export function buildFileTree(entries: { path: string; isDir: boolean }[], sep: string): TreeNode {
  const root: TreeNode = { name: "", isDir: true, children: new Map() };
  for (const entry of entries) {
    const parts = entry.path.split(sep).filter(Boolean);
    let node = root;
    parts.forEach((part, i) => {
      const isLast = i === parts.length - 1;
      let child = node.children.get(part);
      if (!child) {
        child = { name: part, isDir: !isLast || entry.isDir, children: new Map() };
        node.children.set(part, child);
      }
      node = child;
    });
  }
  return root;
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
export function FileTreeView({ node, depth = 0 }: { node: TreeNode; depth?: number }) {
  const entries = [...node.children.values()].sort((a, b) =>
    a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1);
  if (!entries.length) return null;
  return (
    <ul className={depth === 0 ? "fileTree" : "fileTreeChildren"}>
      {entries.map((child) => (
        <li key={child.name}>
          {child.isDir ? (
            <details>
              <summary>
                <span className="fileTreeChevron" />
                <FolderIcon />
                {child.name}
              </summary>
              <FileTreeView node={child} depth={depth + 1} />
            </details>
          ) : (
            <span className="fileTreeFile">
              <FileIcon />
              {child.name}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
