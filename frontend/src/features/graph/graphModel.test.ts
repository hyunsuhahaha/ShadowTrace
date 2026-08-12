import { expect, it } from "vitest";
import { buildActivityFeed, clampActivityPanel, credentialBadge, filterActivityFeed, filterGraph,
  getNodeActivity, initialGraphPosition, initialGraphPositionNearParent,
  isCrackableCredential, nodeStatusReason, nodeSummary } from "./graphModel";

it("formats a credential overlay without exposing secret material", () => {
  expect(credentialBadge({type: "credential", label: "administrator",
    meta: JSON.stringify({domain: "CORP", username: "administrator",
      credType: "hash", secretHint: "NTLM …8f3a"})})).toEqual({
    identity: "CORP\\administrator", kind: "HASH",
  });
});

it("parses only live graph activity metadata", () => {
  expect(getNodeActivity({ meta: JSON.stringify({ activity: {
    kind: "scan", status: "running", label: "Full TCP",
  } }) })).toEqual({ kind: "scan", status: "running", label: "Full TCP",
    startedAt: null });
  expect(getNodeActivity({ meta: JSON.stringify({ activity: {
    kind: "execution", status: "completed", label: "whatweb",
  } }) })).toBeNull();
  expect(getNodeActivity({ meta: "broken" })).toBeNull();
  expect(getNodeActivity({ meta: JSON.stringify({ activity: {
    kind: "listener", status: "launched", label: "RESPONDER",
  } }) })?.kind).toBe("listener");
});

it("routes hash credentials to cracking instead of post-exploitation", () => {
  expect(isCrackableCredential({ type: "credential",
    meta: JSON.stringify({ credType: "hash" }) })).toBe(true);
  expect(isCrackableCredential({ type: "credential",
    meta: JSON.stringify({ credType: "password" }) })).toBe(false);
});

it("preserves settled node positions when graph topology changes", () => {
  const settled = new Map([["host-1", { x: 712, y: 418 }]]);
  expect(initialGraphPosition("host-1", 0, 2, settled)).toEqual({ x: 712, y: 418 });
  expect(initialGraphPosition("service-new", 1, 2, settled)).not.toEqual({ x: 712, y: 418 });
  const child = initialGraphPositionNearParent("execution-42", settled.get("host-1"));
  expect(Math.hypot(child!.x - 712, child!.y - 418)).toBeCloseTo(74);
});

it("summarizes node outcomes and incomplete reasons without empty glyphs", () => {
  expect(nodeSummary({ type: "service", status: "untried", label: "80/tcp http",
    meta: JSON.stringify({ product: "Apache httpd", version: "2.4.52" }) }))
    .toBe("80/tcp http · Apache httpd · 2.4.52");
  expect(nodeSummary({ type: "technique", status: "attempt-failed", label: "whatweb",
    meta: JSON.stringify({ error: "timeout", exitCode: 124 }) }))
    .toBe("timeout · exit 124");
  expect(nodeStatusReason({ type: "technique", status: "in-progress",
    meta: JSON.stringify({ executionStatus: "completed" }) })).toBe("사용자 검토 대기");
  expect(nodeStatusReason({ type: "service", status: "blocked", meta: "{}" }))
    .toBe("선행 정보 부족");
});

it("builds a newest-first clickable activity feed from graph nodes", () => {
  const nodes = [{ id: "svc", type: "service", status: "untried", label: "80/tcp http",
    objective: false, source_ref: "", hidden: false, created_at: "2026-08-09T10:42:38Z",
    meta: JSON.stringify({ product: "Apache", version: "2.4.52" }) },
  { id: "cred", type: "credential", status: "succeeded", label: "Administrator",
    objective: false, source_ref: "", hidden: false, created_at: "2026-08-09T10:46:09Z",
    meta: JSON.stringify({ username: "Administrator", credType: "NetNTLMv2" }) }];
  const feed = buildActivityFeed({ root_node_id: null,
    nodes: nodes as Parameters<typeof buildActivityFeed>[0]["nodes"], edges: [] });
  expect(feed.map((item) => item.nodeId)).toEqual(["cred", "svc"]);
  expect(feed[0].text).toContain("captured");
  expect(filterActivityFeed(feed, "apache", "service").map((item) => item.nodeId))
    .toEqual(["svc"]);
  expect(filterActivityFeed(feed, "administrator", "finding")).toEqual([]);
});

it("keeps a moved or resized activity stream inside the graph", () => {
  expect(clampActivityPanel(900, -20, 280, 180, 1000, 700))
    .toEqual({ x: 692, y: 0 });
});

it("filters and focuses a large graph without deleting the source topology", () => {
  const nodes = ["a", "b", "c"].map((id, index) => ({ id, type: index ? "technique" : "host",
    status: index === 2 ? "attempt-failed" : "untried", label: id, objective: false,
    source_ref: "", hidden: false, notes: id === "b" ? "check headers" : "" }));
  const data = { root_node_id: "a", nodes, edges: [
    { id: "ab", source: "a", target: "b", relation: "attempted", status: "untried" },
    { id: "bc", source: "b", target: "c", relation: "attempted", status: "untried" }] };
  const focused = filterGraph(data as Parameters<typeof filterGraph>[0],
    { query: "", type: "all", status: "all", focusDepth: 1, pinnedOnly: false }, "a");
  expect(focused.nodes.map((node) => node.id)).toEqual(["a", "b"]);
  expect(data.nodes).toHaveLength(3);
});
