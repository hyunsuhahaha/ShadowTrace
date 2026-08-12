// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { GraphCanvas } from "./GraphCanvas";
import type { GraphOut } from "./graphModel";

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
