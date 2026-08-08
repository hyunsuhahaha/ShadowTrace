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

export function FileTreeView({ node }: { node: TreeNode }) {
  const entries = [...node.children.values()].sort((a, b) =>
    a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1);
  if (!entries.length) return null;
  return (
    <ul className="fileTree">
      {entries.map((child) => (
        <li key={child.name}>
          {child.isDir ? (
            <details>
              <summary>{child.name}</summary>
              <FileTreeView node={child} />
            </details>
          ) : (
            <span className="fileTreeFile">{child.name}</span>
          )}
        </li>
      ))}
    </ul>
  );
}
