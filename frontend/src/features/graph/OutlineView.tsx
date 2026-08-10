import { useState } from "react";
import { color, GLYPH, STATUS_REASON, TreeItem, TreeNode } from "./graphModel";
import { S } from "./graphStyles";
import { Empty } from "./graphLeaves";

export function OutlineView(props: {
  tree?: TreeNode; selected: string | null; onSelect: (id: string) => void;
}) {
  if (!props.tree) return <Empty text="Outline 불러오는 중…" />;
  return (
    <div style={S.outline}>
      <Row item={props.tree} depth={0} selected={props.selected} onSelect={props.onSelect} />
    </div>
  );
}

function Row(props: {
  item: TreeItem; depth: number; selected: string | null; onSelect: (id: string) => void;
}) {
  const { item, depth } = props;
  const [open, setOpen] = useState(depth < 2);
  if (item.kind !== "node") {
    return (
      <div style={{ ...S.row, color: "#6aa9ff", fontStyle: "italic" }}>
        <span style={{ width: 14 }} />↗ {item.kind === "cycle" ? "순환 → " : "참조 → "}
        {item.target}
      </div>
    );
  }
  const kids = item.children;
  const hasKids = kids.length > 0;
  const c = color(item.status);
  return (
    <div>
      <div style={{ ...S.row, ...(props.selected === item.id ? S.rowSel : {}) }}
        onClick={() => props.onSelect(item.id)}>
        <span style={{ width: 14, cursor: "pointer", color: "#6b6b76" }}
          onClick={(e) => { e.stopPropagation(); setOpen(!open); }}>
          {hasKids ? (open ? "▾" : "▸") : ""}
        </span>
        <span style={{ width: 18, textAlign: "center" }}>{GLYPH[item.type]}</span>
        <span style={{ flex: 1 }}>{item.label}</span>
        <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 7px",
          borderRadius: 20, background: `${c}22`, color: c }}>
          {(STATUS_REASON[item.status] ?? item.status).toUpperCase()}
        </span>
      </div>
      {open && hasKids && (
        <div style={{ paddingLeft: 22, marginLeft: 10, borderLeft: "1px solid #2a2a34" }}>
          {kids.map((child, i) => (
            <Row key={child.kind === "node" ? child.id : `${child.edgeId}-${i}`}
              item={child} depth={depth + 1}
              selected={props.selected} onSelect={props.onSelect} />
          ))}
        </div>
      )}
    </div>
  );
}
