// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {afterEach, expect, it, vi} from "vitest";
import AutoReconPanel, {formatAutoReconElapsed} from "./AutoReconPanel";
import {FloatingTerminalProvider} from "./FloatingTerminal";
import type {Target} from "./scanCenterModel";

afterEach(cleanup);

it("formats AutoRecon elapsed time in minutes and seconds", () => {
  expect(formatAutoReconElapsed({started_at: "2026-08-16T00:00:00Z", created_at: "",
    id: 1, project_id: 10, target_ids: "[]", command: "autorecon", output_dir: "",
    status: "running", stopped: false, error: "", imported_count: 0},
  new Date("2026-08-16T00:03:07Z").getTime())).toBe("3분 7초");
});

it("treats timezone-less AutoRecon timestamps as server UTC", () => {
  expect(formatAutoReconElapsed({started_at: "2026-08-16T00:00:00", created_at: "",
    id: 1, project_id: 10, target_ids: "[]", command: "autorecon", output_dir: "",
    status: "running", stopped: false, error: "", imported_count: 0},
  Date.parse("2026-08-16T00:01:05Z"))).toBe("1분 5초");
});

const targets: Target[] = [
  {id: 1, project_id: 10, name: "DC01", ip: "10.10.10.10"},
  {id: 2, project_id: 10, name: "", ip: "10.10.10.11"},
];

function renderPanel(overrides: Partial<Parameters<typeof AutoReconPanel>[0]> = {}) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}});
  const props = {
    projectId: 10, targets, selectedIds: new Set<number>(), onToggle: vi.fn(),
    onSelectAll: vi.fn(), onClear: vi.fn(), onStart: vi.fn(), starting: false,
    onSelectRun: vi.fn(),
    ...overrides,
  };
  render(<QueryClientProvider client={client}><FloatingTerminalProvider>
    <AutoReconPanel {...props} />
  </FloatingTerminalProvider></QueryClientProvider>);
  return props;
}

it("lists every target in the project as a checkbox and toggles selection on click", () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  const props = renderPanel();
  expect(screen.getByText("DC01")).toBeTruthy();
  expect(screen.getByText("10.10.10.11")).toBeTruthy();
  fireEvent.click(screen.getByText("10.10.10.10").closest("label")!.querySelector("input")!);
  expect(props.onToggle).toHaveBeenCalledWith(1);
});

it("keeps the start button disabled until scope is acknowledged and a target is selected", () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  const props = renderPanel({selectedIds: new Set([1])});
  const start = screen.getByText(/AutoRecon 시작/);
  expect(start.closest("button")!.disabled).toBe(true);

  fireEvent.click(screen.getByText(/SCOPE ACKNOWLEDGEMENT/).closest("label")!
    .querySelector("input")!);
  expect(start.closest("button")!.disabled).toBe(false);

  fireEvent.click(start);
  expect(props.onStart).toHaveBeenCalled();
});

it("passes native AutoRecon options with the start request", () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  const props = renderPanel({selectedIds: new Set([1])});
  fireEvent.click(screen.getByText(/실행 범위 및 프로필/));
  fireEvent.change(screen.getByText("실행 모드").closest("label")!.querySelector("select")!,
    {target: {value: "quick"}});
  fireEvent.change(screen.getByText("Heartbeat(초)").closest("label")!.querySelector("input")!,
    {target: {value: "30"}});
  fireEvent.click(screen.getByText(/SCOPE ACKNOWLEDGEMENT/).closest("label")!
    .querySelector("input")!);
  fireEvent.click(screen.getByText(/AutoRecon 시작/));
  expect(props.onStart).toHaveBeenCalledWith("--port-scans top-tcp-ports --heartbeat '30'");
});

it("shows an empty state when the project has no AutoRecon runs yet", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  renderPanel();
  expect(await screen.findByText("아직 실행한 AutoRecon이 없습니다.")).toBeTruthy();
});

it("lists runs with their status and target IPs, and selects one on click", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/autorecon?project_id=10")) return Promise.resolve(
      new Response(JSON.stringify([
        {id: 5, project_id: 10, target_ids: "[1,2]", command: "autorecon 10.10.10.10 10.10.10.11",
         output_dir: "/tmp/out", status: "running", stopped: false, error: "",
         imported_count: 0, created_at: "2026-08-16T00:00:00Z"},
      ]), {headers: {"Content-Type": "application/json"}}));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const props = renderPanel();

  expect(await screen.findByText("실행 #5")).toBeTruthy();
  expect(screen.getByText("10.10.10.10, 10.10.10.11")).toBeTruthy();

  fireEvent.click(screen.getByText("실행 #5").closest(".autoReconRunRow")!);
  expect(props.onSelectRun).toHaveBeenCalledWith(5);
});

it("streams the active run's live output over SSE and shows the imported-count summary once it lands", async () => {
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    onopen: (() => void) | null = null;
    onmessage: ((e: {data: string}) => void) | null = null;
    onerror: (() => void) | null = null;
    closed = false;
    constructor(public url: string) { FakeEventSource.instances.push(this); }
    close() { this.closed = true; }
  }
  vi.stubGlobal("EventSource", FakeEventSource as unknown as typeof EventSource);
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/autorecon?project_id=10")) return Promise.resolve(
      new Response(JSON.stringify([
        {id: 5, project_id: 10, target_ids: "[1]", command: "autorecon 10.10.10.10",
         output_dir: "/tmp/out", status: "running", stopped: false, error: "",
         imported_count: 0, created_at: "2026-08-16T00:00:00Z"},
      ]), {headers: {"Content-Type": "application/json"}}));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  renderPanel({activeRunId: 5});

  await screen.findByText(/실행 #5 · running · 경과/);
  const source = FakeEventSource.instances.at(-1)!;
  source.onmessage?.({data: JSON.stringify({stream: "stdout", data: "[*] Scanning 10.10.10.10\n"})});
  expect(await screen.findByText(/Scanning 10.10.10.10/)).toBeTruthy();
  expect(screen.getByText(/마지막 응답 0초 전/)).toBeTruthy();
});

it("replays the backend's snapshot as the full transcript instead of appending it", async () => {
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    onopen: (() => void) | null = null;
    onmessage: ((e: {data: string}) => void) | null = null;
    onerror: (() => void) | null = null;
    constructor(public url: string) { FakeEventSource.instances.push(this); }
    close() {}
  }
  vi.stubGlobal("EventSource", FakeEventSource as unknown as typeof EventSource);
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([
      {id: 5, project_id: 10, target_ids: "[1]", command: "autorecon 10.10.10.10",
       output_dir: "/tmp/out", status: "running", stopped: false, error: "",
       imported_count: 0, created_at: "2026-08-16T00:00:00Z"},
    ]), {headers: {"Content-Type": "application/json"}}))));
  renderPanel({activeRunId: 5});

  await screen.findByText(/실행 #5 · running · 경과/);
  const source = FakeEventSource.instances.at(-1)!;
  // Re-subscribing (e.g. after switching workspaces and back, which
  // unmounts and remounts this component) starts with an empty local
  // `output` state -- the backend's very first event on any new
  // subscription is a "snapshot" carrying everything captured so far,
  // which is what's supposed to repopulate the transcript instead of it
  // looking wiped.
  source.onmessage?.({data: JSON.stringify({
    stream: "snapshot", data: "[*] Scanning target 10.10.10.10\n[*] Discovered open port tcp/22\n",
  })});
  expect(await screen.findByText(/Discovered open port tcp\/22/)).toBeTruthy();
});

it("refreshes the run list and the graph when an incremental import lands mid-run", async () => {
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    onopen: (() => void) | null = null;
    onmessage: ((e: {data: string}) => void) | null = null;
    onerror: (() => void) | null = null;
    constructor(public url: string) { FakeEventSource.instances.push(this); }
    close() {}
  }
  vi.stubGlobal("EventSource", FakeEventSource as unknown as typeof EventSource);
  const calls: string[] = [];
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    calls.push(String(input));
    return Promise.resolve(new Response(JSON.stringify([
      {id: 5, project_id: 10, target_ids: "[1]", command: "autorecon 10.10.10.10",
       output_dir: "/tmp/out", status: "running", stopped: false, error: "",
       imported_count: 0, created_at: "2026-08-16T00:00:00Z"},
    ]), {headers: {"Content-Type": "application/json"}}));
  }));
  const graphRefresh = vi.fn();
  addEventListener("oscp-graph-refresh", graphRefresh);
  renderPanel({activeRunId: 5});

  await screen.findByText(/실행 #5 · running · 경과/);
  const callsBeforeImport = calls.length;
  const source = FakeEventSource.instances.at(-1)!;
  await source.onmessage?.({data: JSON.stringify({stream: "imported", imported_count: 3})});

  expect(graphRefresh).toHaveBeenCalled();
  await vi.waitFor(() => expect(calls.length).toBeGreaterThan(callsBeforeImport));
  removeEventListener("oscp-graph-refresh", graphRefresh);
});

it("floats the transcript when the header is dragged, same as the single-target scan panel", async () => {
  vi.stubGlobal("matchMedia", vi.fn(() => ({
    matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    addListener: vi.fn(), removeListener: vi.fn(),
  })));
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  Object.defineProperties(HTMLElement.prototype, {
    setPointerCapture: {configurable: true, value: vi.fn()},
    hasPointerCapture: {configurable: true, value: () => true},
    releasePointerCapture: {configurable: true, value: vi.fn()},
  });
  vi.stubGlobal("EventSource", class {
    onopen: (() => void) | null = null; onmessage: (() => void) | null = null;
    onerror: (() => void) | null = null;
    constructor(public url: string) {}
    close() {}
  } as unknown as typeof EventSource);
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([
      {id: 5, project_id: 10, target_ids: "[1]", command: "autorecon 10.10.10.10",
       output_dir: "/tmp/out", status: "running", stopped: false, error: "",
       imported_count: 0, created_at: "2026-08-16T00:00:00Z"},
    ]), {headers: {"Content-Type": "application/json"}}))));
  renderPanel({activeRunId: 5});
  const header = await screen.findByText(/실행 #5 · running · 경과/);

  fireEvent.pointerDown(header, {button: 0, pointerId: 1, clientX: 50, clientY: 60});
  fireEvent.pointerMove(header, {pointerId: 1, clientX: 90, clientY: 100});

  expect(await screen.findByLabelText("플로팅 스캔 터미널 #5")).toBeTruthy();
  expect(screen.getByText(/플로팅 창으로 이동됨/)).toBeTruthy();
});
