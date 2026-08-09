// Reverse bridge: a specialized workspace can ask the Progress Graph to focus
// the node that represents a given domain entity. The target graph node is
// identified by its source_ref {kind, id} (e.g. {kind:"service", id:42}).
// Mirrors pendingServiceNav: survives both a fresh GraphWorkspace mount and an
// already-mounted one (via the "oscp-graph-focus" event).
export type PendingGraphFocus = { kind: string; id: number };

let pending: PendingGraphFocus | undefined;

export function setPendingGraphFocus(focus: PendingGraphFocus) {
  pending = focus;
}

export function consumePendingGraphFocus(): PendingGraphFocus | undefined {
  const value = pending;
  pending = undefined;
  return value;
}

// Convenience for reverse-link buttons in other workspaces.
export function focusInGraph(focus: PendingGraphFocus) {
  setPendingGraphFocus(focus);
  location.hash = "#graph";
  dispatchEvent(new CustomEvent("oscp-graph-focus"));
}
