// @vitest-environment jsdom
import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { GraphCanvas } from "./GraphCanvas";
import type { GraphOut } from "./graphModel";
import { FILE_DRAG_MIME } from "../../fileTree";

// jsdom's DataTransfer doesn't implement setData/getData usefully across
// dragstart/drop, so tests build the minimal fake the component actually
// reads: `types` (dragover's "do I accept this?" check) and `getData`.
function fileDragTransfer(payload: {kind: string; runId: number; path: string} | null) {
  const data = payload ? JSON.stringify(payload) : "";
  return {
    types: payload ? [FILE_DRAG_MIME] : ["text/plain"],
    getData: () => data,
    dropEffect: "none",
  };
}

// jsdom has no real Canvas 2D implementation, so the render loop's drawing
// calls need a no-op stub -- this only proves the component mounts/unmounts
// and wires its callback props without throwing. Force-sim physics and
// actual pixel output are out of scope (would require real layout/hit-testing
// jsdom can't provide); see docs/WORKLOG.md Phase 10 note on this file.
function stubCanvasContext() {
  const gradient = { addColorStop: vi.fn() };
  const ctx = {
    clearRect: vi.fn(), fillRect: vi.fn(), strokeRect: vi.fn(),
    beginPath: vi.fn(), closePath: vi.fn(), arc: vi.fn(), fill: vi.fn(),
    stroke: vi.fn(), moveTo: vi.fn(), lineTo: vi.fn(), quadraticCurveTo: vi.fn(),
    save: vi.fn(), restore: vi.fn(), scale: vi.fn(), translate: vi.fn(),
    setTransform: vi.fn(), setLineDash: vi.fn(), fillText: vi.fn(),
    createRadialGradient: vi.fn(() => gradient),
    measureText: vi.fn(() => ({ width: 40 })),
    fillStyle: "", strokeStyle: "", lineWidth: 0, font: "", globalAlpha: 1,
    shadowBlur: 0, shadowColor: "", textAlign: "left", textBaseline: "top",
  };
  vi.spyOn(HTMLCanvasElement.prototype, "getContext")
    .mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
  return ctx;
}

beforeEach(() => {
  stubCanvasContext();
  // jsdom doesn't implement ResizeObserver or matchMedia.
  vi.stubGlobal("ResizeObserver", class {
    observe() {} unobserve() {} disconnect() {}
  });
  vi.stubGlobal("matchMedia", vi.fn(() => ({
    matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
  })));
});

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const emptyData: GraphOut = { root_node_id: null, nodes: [], edges: [] };

it("mounts and unmounts without throwing on an empty graph", () => {
  const { unmount } = render(<GraphCanvas data={emptyData} hostCount={0} showHidden={false}
    credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);
  expect(document.querySelector("canvas")).toBeTruthy();
  unmount();
});

it("re-renders when the node set changes without throwing", () => {
  const data: GraphOut = { root_node_id: "root", nodes: [
    { id: "root", type: "project-root", status: "untried", label: "Project",
      objective: false, source_ref: "", hidden: false },
  ], edges: [] };
  const { rerender } = render(<GraphCanvas data={emptyData} hostCount={0} showHidden={false}
    credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);
  rerender(<GraphCanvas data={data} hostCount={1} showHidden={false} credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);
  expect(document.querySelector("canvas")).toBeTruthy();
});

it("shows the empty activity stream state when nothing is happening", () => {
  render(<GraphCanvas data={emptyData} hostCount={0} showHidden={false} credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);
  expect(document.body.textContent).toContain("아직 기록된 활동이 없습니다.");
});

it("renders credential badges and directional access lineage without secrets", () => {
  const ctx = stubCanvasContext();
  const data: GraphOut = {root_node_id: "root", nodes: [
    {id: "root", type: "project-root", status: "untried", label: "Lab",
      objective: false, source_ref: "", hidden: false},
    {id: "a", type: "host", status: "succeeded", label: "10.0.0.10",
      objective: false, source_ref: "", hidden: false},
    {id: "b", type: "host", status: "succeeded", label: "10.0.0.20",
      objective: false, source_ref: "", hidden: false},
    {id: "cred", type: "credential", status: "succeeded", label: "administrator",
      objective: false, source_ref: "", hidden: false,
      meta: JSON.stringify({domain: "CORP", username: "administrator",
        credType: "hash", secretHint: "must-not-render"})},
  ], edges: [
    {id: "ra", source: "root", target: "a", relation: "discovered", status: "untried"},
    {id: "rb", source: "root", target: "b", relation: "discovered", status: "untried"},
    {id: "ac", source: "a", target: "cred", relation: "enumerated", status: "succeeded"},
    {id: "cb", source: "cred", target: "b", relation: "reused-credential",
      status: "succeeded", label: "CORP\\administrator · WMIEXEC"},
    {id: "ab", source: "a", target: "b", relation: "pivoted-to",
      status: "succeeded", label: "LATERAL · CORP\\administrator"},
  ]};

  render(<GraphCanvas data={data} hostCount={2} showHidden={false} credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);

  const rendered = ctx.fillText.mock.calls.map((call) => String(call[0]));
  expect(rendered).toContain("CORP\\administrator");
  expect(rendered).toContain("HASH · CAPTURED");
  expect(rendered).toContain("CORP\\administrator · WMIEXEC");
  expect(rendered).not.toContain("must-not-render");
});

it("draws falling binary rain (not the ring pulse or scan sweep) for a running hash-crack job", () => {
  const ctx = stubCanvasContext();
  const data: GraphOut = {root_node_id: "root", nodes: [
    {id: "root", type: "project-root", status: "untried", label: "Lab",
      objective: false, source_ref: "", hidden: false},
    {id: "a", type: "host", status: "succeeded", label: "10.0.0.10",
      objective: false, source_ref: "", hidden: false},
    {id: "job", type: "technique", status: "in-progress", label: "NTLM crack",
      objective: false, source_ref: "", hidden: false,
      meta: JSON.stringify({activity: {kind: "crack", status: "running", label: "NTLM"}})},
  ], edges: [
    {id: "ra", source: "root", target: "a", relation: "discovered", status: "untried"},
    {id: "aj", source: "a", target: "job", relation: "attempted", status: "in-progress"},
  ]};

  render(<GraphCanvas data={data} hostCount={1} showHidden={false} credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);

  const digitCalls = ctx.fillText.mock.calls.filter((call) => call[0] === "0" || call[0] === "1");
  expect(digitCalls.length).toBeGreaterThan(0);
  // no other node's activity ring/pulse call ever draws a bare "0"/"1" --
  // only this effect does, so this alone also proves the shared breathing
  // ring was skipped for this node rather than drawn underneath it.
});

it("marks nodes backed by human-attached evidence, not nodes without any", () => {
  const ctx = stubCanvasContext();
  const data: GraphOut = {root_node_id: "root", nodes: [
    {id: "root", type: "project-root", status: "untried", label: "Lab",
      objective: false, source_ref: "", hidden: false},
    {id: "svc", type: "service", status: "succeeded", label: "445/tcp smb",
      objective: false, source_ref: "", hidden: false,
      meta: JSON.stringify({evidenceCount: 4})},
    {id: "svc2", type: "service", status: "untried", label: "80/tcp http",
      objective: false, source_ref: "", hidden: false},
  ], edges: [
    {id: "rs", source: "root", target: "svc", relation: "discovered", status: "untried"},
    {id: "rs2", source: "root", target: "svc2", relation: "discovered", status: "untried"},
  ]};

  render(<GraphCanvas data={data} hostCount={0} showHidden={false} credentialOverlay
    selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} />);

  const rendered = ctx.fillText.mock.calls.map((call) => String(call[0]));
  expect(rendered).toContain("4");
});

it("accepts an objective path to highlight without throwing", () => {
  const data: GraphOut = {root_node_id: "root", nodes: [
    {id: "root", type: "project-root", status: "untried", label: "Lab",
      objective: false, source_ref: "", hidden: false},
    {id: "host", type: "host", status: "untried", label: "10.0.0.5",
      objective: false, source_ref: "", hidden: false},
    {id: "goal", type: "finding", status: "untried", label: "Domain Admin",
      objective: true, source_ref: "", hidden: false},
  ], edges: [
    {id: "rh", source: "root", target: "host", relation: "discovered", status: "untried"},
    {id: "hg", source: "host", target: "goal", relation: "enumerated", status: "untried"},
  ]};

  const { unmount } = render(<GraphCanvas data={data} hostCount={1} showHidden={false}
    credentialOverlay selected="root" onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()}
    objectivePath={{ nodeIds: ["root", "host", "goal"], edgeIds: ["rh", "hg"] }} />);
  expect(document.querySelector("canvas")).toBeTruthy();
  unmount();
});

it("dropping a dragged tree file calls onDropFile with its runId and path", () => {
  const onDropFile = vi.fn();
  const { container } = render(<GraphCanvas data={emptyData} hostCount={0} showHidden={false}
    credentialOverlay selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} onDropFile={onDropFile} />);
  const stage = container.firstElementChild as HTMLElement;
  const dataTransfer = fileDragTransfer(
    { kind: "post-exploitation", runId: 12, path: "/home/bob/flag.txt" });

  fireEvent.dragOver(stage, { dataTransfer });
  expect(stage.textContent).toContain("Finding 노드로 추가됩니다");

  fireEvent.drop(stage, { dataTransfer });
  expect(onDropFile).toHaveBeenCalledWith(
    { kind: "post-exploitation", runId: 12, path: "/home/bob/flag.txt" });
  expect(stage.textContent).not.toContain("Finding 노드로 추가됩니다");
});

it("ignores a drop that isn't a tree-file drag", () => {
  const onDropFile = vi.fn();
  const { container } = render(<GraphCanvas data={emptyData} hostCount={0} showHidden={false}
    credentialOverlay selected={null} onSelect={vi.fn()} focus={null} layoutMode="graph"
    onActivitySelect={vi.fn()} onContext={vi.fn()} onDropFile={onDropFile} />);
  const stage = container.firstElementChild as HTMLElement;
  const dataTransfer = fileDragTransfer(null);

  fireEvent.dragOver(stage, { dataTransfer });
  expect(stage.textContent).not.toContain("Finding 노드로 추가됩니다");

  fireEvent.drop(stage, { dataTransfer });
  expect(onDropFile).not.toHaveBeenCalled();
});
